#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-ubwc-a2-rd-switch");
KPM_VERSION("1.2.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("A2 IFE RD acquire-path probe");

/*
 * Confirmed from the target OnePlus kernel source:
 *
 * cam_isp_ife.h:
 *
 *   #define CAM_ISP_IFE_IN_RES_BASE 0x4000
 *   #define CAM_ISP_IFE_IN_RES_RD   (CAM_ISP_IFE_IN_RES_BASE + 7)
 *
 * Therefore:
 *
 *   CAM_ISP_IFE_IN_RES_RD = 0x4007
 */
#define CAM_ISP_IFE_IN_RES_RD 0x4007U


/*
 * struct cam_hw_acquire_stream_caps
 *
 * From:
 * drivers/cam_core/cam_hw_mgr_intf.h
 */
struct kp_cam_hw_acquire_stream_caps {
    unsigned int num_valid_params;
    unsigned int param_list[4];
};


/*
 * struct cam_hw_acquire_args
 *
 * From:
 * drivers/cam_core/cam_hw_mgr_intf.h
 */
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
 * struct cam_isp_acquire_hw_info
 *
 * Fields confirmed from cam_ife_hw_mgr.c usage.
 */
struct kp_cam_isp_acquire_hw_info {
    unsigned int num_inputs;
    unsigned int input_info_size;
    unsigned int input_info_offset;
    unsigned int input_info_version;

    unsigned char data[1];
};


/*
 * struct cam_isp_in_port_info_v2
 *
 * Layout confirmed from cam_isp.h:
 *
 *   res_type
 *   lane_type
 *   lane_num
 *   lane_cfg
 *   vc[]
 *   dt[]
 *   num_valid_vc_dt
 *   format
 *   test_pattern
 *   usage_type
 *   ...
 *   num_out_res
 *   offline_mode
 *   ...
 *
 * This first-stage probe only needs fields through sfe_in_path_type.
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
 * Global state.
 */
static unsigned long acquire_addr;
static volatile int armed;
static volatile unsigned int switch_count;


/*
 * Dump input-port information.
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
 * Identify a normal pixel input candidate.
 *
 * We intentionally keep the first version conservative.
 */
static int is_candidate_pixel_input(
    const struct kp_cam_isp_in_port_info_v2 *in)
{
    if (!in)
        return 0;

    /*
     * No output resource -> not our target.
     */
    if (!in->num_out_res)
        return 0;

    /*
     * Invalid geometry -> not our target.
     */
    if (!in->left_width || !in->height)
        return 0;

    /*
     * Already RD -> don't modify.
     */
    if (in->res_type == CAM_ISP_IFE_IN_RES_RD)
        return 0;

    /*
     * Don't touch SFE fetch paths in this first version.
     */
    if (in->sfe_in_path_type)
        return 0;

    return 1;
}


/*
 * Hook:
 *
 * static int cam_ife_mgr_acquire(
 *     void *hw_mgr_priv,
 *     void *acquire_hw_args)
 */
static void before_acquire(
    hook_fargs2_t *args,
    void *udata)
{
    struct kp_cam_hw_acquire_args *acq;
    struct kp_cam_isp_acquire_hw_info *info;
    struct kp_cam_isp_in_port_info_v2 *in;
    unsigned int i;

    if (!args)
        return;

    /*
     * Always print this first.
     *
     * This lets us confirm whether the hook is really entered.
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
     * Important:
     *
     * arg1 is already void *acquire_hw_args.
     * Do NOT dereference arg1 again.
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

    if (!acq->acquire_info)
        return;

    if (!acq->acquire_info_size)
        return;

    if (!acq->num_acq || acq->num_acq > 16)
        return;

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

    if (!info->num_inputs || info->num_inputs > 16)
        return;

    if (info->input_info_offset >= info->input_info_size)
        return;

    /*
     * The v2 parser in cam_ife_hw_mgr.c computes:
     *
     *   in_port =
     *       (uint8_t *)&acquire_hw_info->data +
     *       input_info_offset;
     */
    in = (struct kp_cam_isp_in_port_info_v2 *)
        ((unsigned char *)&info->data[0] +
         info->input_info_offset);

    /*
     * First-stage test:
     *
     * Only inspect the first input.
     *
     * We deliberately do not walk variable-length output-port
     * records here yet.
     */
    for (i = 0; i < 1; i++) {

        dump_port(i, in, "before");

        if (!is_candidate_pixel_input(in)) {
            pr_info(
                "cam-a2: port %u is not candidate\n",
                i);
            break;
        }

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
         * Experimental A2 switch:
         *
         * normal pixel source
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

    pr_info(
        "cam-a2: acquire processed "
        "num_inputs=%u "
        "input_ver=0x%x "
        "switches=%u\n",
        info->num_inputs,
        info->input_info_version,
        switch_count);
}


/*
 * KPM initialization.
 */
static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    acquire_addr = 0;
    armed = 0;
    switch_count = 0;

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
 * Runtime control:
 *
 *   on
 *   off
 *   status
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
 * KPM unload.
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
