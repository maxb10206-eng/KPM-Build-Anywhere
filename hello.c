#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kutils.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-ubwc-config-probe");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Probe runtime UBWC v2 config");

struct kp_ubwc_plane {
    unsigned int port_type,meta_stride,meta_size,meta_offset;
    unsigned int packer_config,mode_config_0,mode_config_1,tile_config;
    unsigned int h_init,v_init,static_ctrl,ctrl_2,stats_ctrl_2;
    unsigned int lossy_threshold_0,lossy_threshold_1,lossy_var_offset;
    unsigned int bandwidth_limit,reserved[3];
};

struct kp_ubwc_config_v2 {
    unsigned int api_version,num_ports;
    struct kp_ubwc_plane ubwc_plane_cfg[8];
};

static unsigned long addr_ubwc;
static volatile int armed;

static void before_ubwc(
    hook_fargs3_t *args,void *udata)
{
    struct kp_ubwc_config_v2 *cfg;
    unsigned int i,n;

    if (!armed)
        return;

    /*
     * cam_isp_blob_ubwc_update_v2(
     *     uint32_t blob_type,
     *     struct cam_isp_generic_blob_info *blob_info,
     *     struct cam_ubwc_config_v2 *ubwc_config,
     *     struct cam_hw_prepare_update_args *prepare)
     *
     * hook_fargs3 这里取第三个参数。
     */
    cfg = (struct kp_ubwc_config_v2 *)args->arg3;
    if (!cfg)
        return;

    n = cfg->num_ports;
    if (n > 8)
        n = 8;

    pr_info(
        "cam-ubwc: HIT api=%u ports=%u\n",
        cfg->api_version,n);

    for (i = 0; i < n; i++) {
        struct kp_ubwc_plane *p =
            &cfg->ubwc_plane_cfg[i];

        pr_info(
            "cam-ubwc: P[%u] port=0x%x "
            "meta_stride=%u meta_size=%u meta_off=%u\n",
            i,p->port_type,
            p->meta_stride,
            p->meta_size,
            p->meta_offset);

        pr_info(
            "cam-ubwc: P[%u] pack=0x%x "
            "mode0=0x%x mode1=0x%x tile=0x%x\n",
            i,p->packer_config,
            p->mode_config_0,
            p->mode_config_1,
            p->tile_config);

        pr_info(
            "cam-ubwc: P[%u] h=%u v=%u "
            "static=0x%x ctrl2=0x%x stats2=0x%x\n",
            i,p->h_init,p->v_init,
            p->static_ctrl,
            p->ctrl_2,
            p->stats_ctrl_2);

        pr_info(
            "cam-ubwc: P[%u] "
            "lossy0=0x%x lossy1=0x%x "
            "var=0x%x bw=0x%x\n",
            i,
            p->lossy_threshold_0,
            p->lossy_threshold_1,
            p->lossy_var_offset,
            p->bandwidth_limit);
    }

    armed = 0;
    pr_info("cam-ubwc: probe complete\n");
}

static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    addr_ubwc =
        kallsyms_lookup_name(
            "cam_isp_blob_ubwc_update_v2");

    pr_info(
        "cam-ubwc: ubwc_v2=%lx\n",
        addr_ubwc);

    if (!addr_ubwc) {
        pr_info(
            "cam-ubwc: symbol not found\n");
        return -1;
    }

    if (hook_wrap3(
        (void *)addr_ubwc,
        before_ubwc,
        NULL,NULL))
        return -1;

    pr_info("cam-ubwc: init ok\n");
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
        armed = 1;
        pr_info("cam-ubwc: armed\n");
        compat_copy_to_user(
            out_msg,"armed",6);

    } else if (args[0] == 's') {
        armed = 0;
        pr_info("cam-ubwc: stopped\n");
        compat_copy_to_user(
            out_msg,"stopped",8);
    }

    return 0;
}

static long cam_kpm_exit(void *reserved)
{
    armed = 0;

    if (addr_ubwc)
        unhook((void *)addr_ubwc);

    pr_info("cam-ubwc: exit\n");
    return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
