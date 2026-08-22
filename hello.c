#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kputils.h>
#include <hook.h>

/*
 * A2 第一阶段：
 *
 * cam_ife_mgr_acquire()
 *      ↓
 * cam_hw_acquire_args
 *      ↓
 * cam_isp_acquire_hw_info
 *      ↓
 * cam_isp_in_port_info_v2
 *      ↓
 * res_type = CAM_ISP_IFE_IN_RES_RD
 * offline_mode = 1
 *
 * 这一版只验证 acquire 路径，不替换帧内容。
 */

KPM_NAME("cam-ubwc-a2-rd-switch");
KPM_VERSION("1.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("A2 IFE RD acquire-path probe");

#define CAM_API_COMPAT_CONSTANT 1

/*
 * 这里不要再硬编码 CAM_ISP_IFE_IN_RES_BASE。
 *
 * 你的 kernel 源码里：
 *
 *   #define CAM_ISP_IFE_IN_RES_RD
 *       (CAM_ISP_IFE_IN_RES_BASE + 7)
 *
 * 因此优先直接包含你实际 OnePlus kernel 的 UAPI 头。
 *
 * 如果你的 Makefile 已经提供：
 *
 *   -I.../vendor/qcom/opensource/camera-kernel/include/uapi
 *
 * 那么下面这个 include 可以直接工作。
 */
#include <camera/media/cam_isp_ife.h>

/*
 * cam_hw_acquire_args
 *
 * 来自：
 * drivers/cam_core/cam_hw_mgr_intf.h
 */
struct kp_cam_hw_acquire_stream_caps {
    unsigned int num_valid_params;
    unsigned int param_list[4];
};

struct kp_cam_hw_acquire_args {
    void *context_data;
    unsigned int ctx_id;
    void *event_cb;
    unsigned int num_acq;
    unsigned int acquire_info_size;
    uintptr_t acquire_info;

    void *ctxt_to_hw_map;
    unsigned int hw_mgr_ctx_id;
    unsigned int op_flags;

    unsigned int acquired_hw_id[8];
    unsigned int acquired_hw_path[8][2];
    unsigned int valid_acquired_hw;

    struct kp_cam_hw_acquire_stream_caps op_params;
    void *mini_dump_cb;
};

/*
 * cam_isp_acquire_hw_info
 *
 * 这里我们只使用前面的固定字段。
 * data[] 不需要知道具体内容。
 */
struct kp_cam_isp_acquire_hw_info {
    unsigned int num_inputs;
    unsigned int input_info_size;
    unsigned int input_info_offset;
    unsigned int input_info_version;
    unsigned char data[1];
};

/*
 * cam_isp_in_port_info_v2
 *
 * 来自：
 * vendor/qcom/opensource/camera-kernel/include/uapi/camera/media/cam_isp.h
 *
 * 这里保留到 offline_mode 之前及其后需要的字段。
 *
 * 关键布局：
 *
 * 0x00 res_type
 * ...
 * 0x64 num_out_res
 * 0x68 offline_mode
 *
 * 后面的 data[] 本版本不处理。
 */
struct kp_cam_isp_in_port_info_v2 {
    unsigned int res_type;

    unsigned int lane_type;
    unsigned int lane_num;
    unsigned int lane_cfg;

    unsigned int vc[4];
    unsigned int dt[4];

    unsigned int num_valid_vc_dt;
    unsigned int format;
    unsigned int test_pattern;
    unsigned int usage_type;

    unsigned int left_start;
    unsigned int left_stop;
    unsigned int left_width;

    unsigned int right_start;
    unsigned int right_stop;
    unsigned int right_width;

    unsigned int line_start;
    unsigned int line_stop;
    unsigned int height;

    unsigned int pixel_clk;
    unsigned int batch_size;
    unsigned int dsp_mode;
    unsigned int hbi_cnt;

    unsigned int cust_node;
    unsigned int num_out_res;

    unsigned int offline_mode;

    unsigned int bidirectional_bin;
    unsigned int qcfa_bin;
    unsigned int sfe_in_path_type;
    unsigned int feature_flag;
    unsigned int ife_res_1;
    unsigned int ife_res_2;
};

/*
 * 状态
 */
static unsigned long acquire_addr;
static volatile int armed;
static volatile unsigned int switch_count;

/*
 * 输出一份输入端信息。
 */
static void dump_port(
    unsigned int index,
    const struct kp_cam_isp_in_port_info_v2 *in,
    const char *tag)
{
    if (!in)
        return;

    pr_info(
        "cam-a2: %s "
        "port=%u "
        "res=0x%x "
        "fmt=0x%x "
        "test=%u "
        "w=%u "
        "h=%u "
        "out=%u "
        "offline=%u "
        "sfe_path=0x%x\n",
        tag,
        index,
        in->res_type,
        in->format,
        in->test_pattern,
        in->left_width,
        in->height,
        in->num_out_res,
        in->offline_mode,
        in->sfe_in_path_type);
}

/*
 * 判断是否像一个正常 Pixel 输入。
 *
 * 第一版故意保守：
 *
 * 1. 必须有输出资源
 * 2. 必须有有效尺寸
 * 3. 不能已经是 RD
 * 4. 不处理 SFE RD
 * 5. 不处理纯 RDI
 */
static int is_candidate_pixel_input(
    const struct kp_cam_isp_in_port_info_v2 *in)
{
    if (!in)
        return 0;

    if (!in->num_out_res)
        return 0;

    if (!in->left_width || !in->height)
        return 0;

    if (in->res_type == CAM_ISP_IFE_IN_RES_RD)
        return 0;

    /*
     * SFE RD / Fetch 类型先不要碰。
     */
    if (in->sfe_in_path_type)
        return 0;

    return 1;
}

/*
 * cam_ife_mgr_acquire(
 *      void *hw_mgr_priv,
 *      void *acquire_hw_args
 * )
 *
 * hook_fargs2_t：
 *
 * args->arg0 = 第一个参数
 * args->arg1 = 第二个参数
 *
 * 这里最重要的修正：
 *
 * 错误：
 *   *(struct ... **)args->arg1
 *
 * 正确：
 *   (struct ... *)args->arg1
 */
static void before_acquire(
    hook_fargs2_t *args,
    void *udata)
{
    struct kp_cam_hw_acquire_args *acq;
    struct kp_cam_isp_acquire_hw_info *info;
    struct kp_cam_isp_in_port_info_v2 *in;
    unsigned int i;

    if (!args) {
        return;
    }

    /*
     * 最早日志。
     *
     * 这一条最重要。
     *
     * 如果打开相机后能看到：
     *
     *   cam-a2: ENTER acquire
     *
     * 就证明 hook 真正进入了 cam_ife_mgr_acquire。
     */
    pr_info(
        "cam-a2: ENTER acquire arg0=%pK arg1=%pK armed=%d\n",
        args->arg0,
        args->arg1,
        armed);

    if (!armed)
        return;

    if (!args->arg1)
        return;

    /*
     * 修正后的参数读取方式。
     */
    acq = (struct kp_cam_hw_acquire_args *)args->arg1;

    if (!acq)
        return;

    pr_info(
        "cam-a2: acquire args=%pK "
        "num_acq=%u "
        "info=%pK "
        "info_size=%u "
        "ctx_id=%u\n",
        acq,
        acq->num_acq,
        (void *)acq->acquire_info,
        acq->acquire_info_size,
        acq->ctx_id);

    if (!acq->acquire_info) {
        pr_info("cam-a2: acquire_info=NULL\n");
        return;
    }

    if (!acq->acquire_info_size) {
        pr_info("cam-a2: acquire_info_size=0\n");
        return;
    }

    if (acq->num_acq == 0 || acq->num_acq > 16) {
        pr_info(
            "cam-a2: invalid num_acq=%u\n",
            acq->num_acq);
        return;
    }

    info = (struct kp_cam_isp_acquire_hw_info *)
        (uintptr_t)acq->acquire_info;

    pr_info(
        "cam-a2: acquire_info "
        "num_inputs=%u "
        "input_info_size=%u "
        "input_info_offset=0x%x "
        "input_info_version=0x%x\n",
        info->num_inputs,
        info->input_info_size,
        info->input_info_offset,
        info->input_info_version);

    if (!info->num_inputs || info->num_inputs > 16) {
        pr_info(
            "cam-a2: invalid num_inputs=%u\n",
            info->num_inputs);
        return;
    }

    if (info->input_info_offset >= info->input_info_size) {
        pr_info(
            "cam-a2: invalid input offset=0x%x size=0x%x\n",
            info->input_info_offset,
            info->input_info_size);
        return;
    }

    in = (struct kp_cam_isp_in_port_info_v2 *)
        ((unsigned char *)info->data +
         info->input_info_offset);

    /*
     * 第一版只处理第一个输入。
     *
     * 不在这里根据 data[] 大小继续跨 input，
     * 避免因为 vendor 结构体大小差异产生越界。
     */
    for (i = 0; i < 1; i++) {

        dump_port(i, in, "before");

        if (!is_candidate_pixel_input(in)) {
            pr_info(
                "cam-a2: port %u is not candidate\n",
                i);
            break;
        }

        /*
         * 记录原始状态。
         */
        pr_info(
            "cam-a2: SWITCH port=%u "
            "old_res=0x%x "
            "old_offline=%u "
            "new_res=0x%x "
            "new_offline=1\n",
            i,
            in->res_type,
            in->offline_mode,
            CAM_ISP_IFE_IN_RES_RD);

        /*
         * 核心实验：
         *
         * 普通 Pixel input
         *        ↓
         * IFE RD input
         */
        in->res_type = CAM_ISP_IFE_IN_RES_RD;
        in->offline_mode = 1;

        dump_port(i, in, "after");

        switch_count++;

        pr_info(
            "cam-a2: SWITCH SUCCESS count=%u\n",
            switch_count);

        break;
    }
}

/*
 * KPM init
 */
static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    acquire_addr = 0;
    armed = 0;
    switch_count = 0;

    /*
     * 找 cam_ife_mgr_acquire。
     */
    acquire_addr =
        kallsyms_lookup_name("cam_ife_mgr_acquire");

    pr_info(
        "cam-a2: acquire=%lx\n",
        acquire_addr);

    if (!acquire_addr) {
        pr_err(
            "cam-a2: cam_ife_mgr_acquire not found\n");
        return -1;
    }

    /*
     * 安装 hook。
     */
    if (hook_wrap2(
            (void *)acquire_addr,
            before_acquire,
            NULL,
            NULL)) {

        pr_err(
            "cam-a2: hook_wrap2 failed\n");

        acquire_addr = 0;
        return -1;
    }

    pr_info(
        "cam-a2: init ok\n");

    return 0;
}

/*
 * control0
 *
 * on     -> 开启实验
 * off    -> 关闭实验
 * status -> 查看状态
 */
static long cam_kpm_control0(
    const char *args,
    char __user *out_msg,
    int outlen)
{
    if (!args)
        return -EINVAL;

    /*
     * on
     */
    if (args[0] == 'o' &&
        args[1] == 'n' &&
        args[2] == '\0') {

        armed = 1;

        pr_info(
            "cam-a2: armed switches=%u\n",
            switch_count);

        if (out_msg && outlen >= 6)
            compat_copy_to_user(
                out_msg,
                "armed",
                6);

        return 0;
    }

    /*
     * off
     */
    if (args[0] == 'o' &&
        args[1] == 'f' &&
        args[2] == 'f' &&
        args[3] == '\0') {

        armed = 0;

        pr_info(
            "cam-a2: disarmed switches=%u\n",
            switch_count);

        if (out_msg && outlen >= 4)
            compat_copy_to_user(
                out_msg,
                "off",
                4);

        return 0;
    }

    /*
     * status
     */
    if (args[0] == 's' &&
        args[1] == 't' &&
        args[2] == 'a' &&
        args[3] == 't' &&
        args[4] == 'u' &&
        args[5] == 's' &&
        args[6] == '\0') {

        pr_info(
            "cam-a2: status armed=%d switches=%u\n",
            armed,
            switch_count);

        if (out_msg && outlen >= 6)
            compat_copy_to_user(
                out_msg,
                armed ? "armed" : "off",
                armed ? 6 : 4);

        return 0;
    }

    return -EINVAL;
}

/*
 * KPM exit
 */
static long cam_kpm_exit(
    void *reserved)
{
    armed = 0;

    if (acquire_addr) {
        unhook((void *)acquire_addr);
        acquire_addr = 0;
    }

    pr_info(
        "cam-a2: exit switches=%u\n",
        switch_count);

    return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
