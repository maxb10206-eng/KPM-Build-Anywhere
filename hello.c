#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-preview-format-probe");
KPM_VERSION("1.7.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Probe IFE output formats at acquire_hw");

#define MAX_RES 64

struct kp_cam_isp_out_port {
    unsigned int res_type;
    unsigned int format;
    unsigned int width;
    unsigned int height;
    unsigned int comp_grp_id;
    unsigned int split_point;
    unsigned int secure_mode;
    unsigned int reserved;
};

struct kp_cam_isp_in_port {
    unsigned int res_type;
    unsigned int lane_type, lane_num, lane_cfg;
    unsigned int vc, dt, num_valid_vc_dt;
    unsigned int format;
    unsigned int test_pattern, usage_type;
    unsigned int left_start, left_stop, left_width;
    unsigned int right_start, right_stop, right_width;
    unsigned int line_start, line_stop, height;
    unsigned int pixel_clk, batch_size, dsp_mode, hbi_cnt;
    unsigned int cust_node, horizontal_bin, qcfa_bin;
    unsigned int num_out_res;
    struct kp_cam_isp_out_port data[1];
};

struct kp_cam_isp_acquire_hw_info {
    unsigned int input_info_offset;
    unsigned int input_info_size;
    unsigned int input_info_version;
    unsigned int num_inputs;
    unsigned char data[1];
};

struct kp_cam_hw_acquire_args {
    unsigned int num_acq;
    unsigned int reserved0;
    void *acquire_info;
    unsigned int acquire_info_size;
    unsigned int reserved1;
    void *context_data;
    void *event_cb;
    void *mini_dump_cb;
};

static unsigned long addr_acquire;
static volatile unsigned int probe_count;

static void before_acquire(
    hook_fargs2_t *args, void *udata)
{
    struct kp_cam_hw_acquire_args *a;
    struct kp_cam_isp_acquire_hw_info *info;
    unsigned char *base, *p;
    unsigned int i, j, n;
    struct kp_cam_isp_in_port *in;
    struct kp_cam_isp_out_port *out;

    a = (struct kp_cam_hw_acquire_args *)args->arg1;
    if (!a || !a->acquire_info || !a->acquire_info_size)
        return;

    info =
        (struct kp_cam_isp_acquire_hw_info *)
        a->acquire_info;

    if (!info->input_info_size ||
        !info->input_info_offset ||
        info->num_inputs > MAX_RES)
        return;

    base = (unsigned char *)&info->data[0];
    p = base + info->input_info_offset;

    pr_info(
        "cam-probe: ACQUIRE inputs=%u ver=0x%x size=%u off=%u\n",
        info->num_inputs,
        info->input_info_version,
        a->acquire_info_size,
        info->input_info_offset);

    for (i = 0; i < info->num_inputs; i++) {
        in = (struct kp_cam_isp_in_port *)p;
        n = in->num_out_res;

        if (!n || n > MAX_RES)
            return;

        pr_info(
            "cam-probe: IN[%u] res=%u outs=%u fmt=%u "
            "w=%u h=%u\n",
            i,
            in->res_type,
            n,
            in->format,
            in->left_width,
            in->height);

        for (j = 0; j < n; j++) {
            out = &in->data[j];

            pr_info(
                "cam-probe: OUT[%u][%u] "
                "res=%u fmt=%u w=%u h=%u grp=%u secure=%u\n",
                i,
                j,
                out->res_type,
                out->format,
                out->width,
                out->height,
                out->comp_grp_id,
                out->secure_mode);
        }

        p += sizeof(struct kp_cam_isp_in_port) +
             (n - 1) * sizeof(struct kp_cam_isp_out_port);

        if (++probe_count > 256)
            return;
    }
}

static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    addr_acquire =
        kallsyms_lookup_name(
            "cam_ife_mgr_acquire_hw");

    pr_info(
        "cam-probe: acquire=%lx\n",
        addr_acquire);

    if (!addr_acquire)
        return -1;

    if (hook_wrap2(
        (void *)addr_acquire,
        before_acquire,
        NULL,
        NULL))
        return -1;

    pr_info(
        "cam-probe: init ok\n");

    return 0;
}

static long cam_kpm_control0(
    const char *args,
    char __user *out_msg,
    int outlen)
{
    if (!args)
        return -1;

    if (args[0] == 'c') {
        probe_count = 0;

        pr_info(
            "cam-probe: armed\n");

        compat_copy_to_user(
            out_msg,
            "armed",
            6);

    } else if (args[0] == 's') {
        pr_info(
            "cam-probe: stop count=%u\n",
            probe_count);

        compat_copy_to_user(
            out_msg,
            "stopped",
            8);
    }

    return 0;
}

static long cam_kpm_exit(void *reserved)
{
    if (addr_acquire)
        unhook((void *)addr_acquire);

    pr_info(
        "cam-probe: exit\n");

    return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
