#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-preview-format-probe");
KPM_VERSION("1.7.2");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Probe Camera output format from prepare");

#define CAM_BUF_OUTPUT 2

struct kp_cam_packet_header {
    unsigned int op_code,size;
    unsigned long long request_id;
    unsigned int flags,padding;
};

struct kp_cam_packet {
    struct kp_cam_packet_header header;
    unsigned int cmd_buf_offset,num_cmd_buf;
    unsigned int io_configs_offset,num_io_configs;
    unsigned int patch_offset,num_patches;
    unsigned int kmd_cmd_buf_index,kmd_cmd_buf_offset;
    unsigned long long payload[1];
};

struct kp_cam_plane_cfg {
    unsigned int width,height,plane_stride,slice_height;
    unsigned int meta_stride,meta_size,meta_offset;
    unsigned int packer_config,mode_config,tile_config;
    unsigned int h_init,v_init;
};

struct kp_cam_cmd_buf_desc {
    int mem_handle;
    unsigned int offset,size,length,type,meta_data;
};

struct kp_cam_buf_io_cfg {
    int mem_handle[3];
    unsigned int offsets[3];
    struct kp_cam_plane_cfg planes[3];
    unsigned int format,color_space,color_pattern,bpp,rotation;
    unsigned int resource_type;
    int fence,early_fence;
    struct kp_cam_cmd_buf_desc aux_cmd_buf;
    unsigned int direction,batch_size;
    unsigned int subsample_pattern,subsample_period;
    unsigned int framedrop_pattern,framedrop_period;
    unsigned int flag,padding;
};

static unsigned long addr_prepare;
static volatile int armed;

static void before_prepare(
    hook_fargs2_t *args,void *udata)
{
    struct kp_cam_packet *p;
    struct kp_cam_buf_io_cfg *io;
    unsigned int i;

    if (!armed)
        return;

    p = *(struct kp_cam_packet **)args->arg1;
    if (!p)
        return;

    if (!p->num_io_configs ||
        p->num_io_configs > 64)
        return;

    io = (struct kp_cam_buf_io_cfg *)(
        (unsigned char *)p->payload +
        p->io_configs_offset);

    pr_info(
        "cam-probe: PREP req=%llu "
        "num_io=%u offset=%u\n",
        p->header.request_id,
        p->num_io_configs,
        p->io_configs_offset);

    for (i = 0; i < p->num_io_configs; i++) {

        pr_info(
            "cam-probe: IO[%u] "
            "dir=%u res=0x%x fmt=%u "
            "w=%u h=%u stride=%u slice=%u "
            "off=%u mem0=0x%x "
            "plane_fmt=%u bpp=%u\n",
            i,
            io[i].direction,
            io[i].resource_type,
            io[i].format,
            io[i].planes[0].width,
            io[i].planes[0].height,
            io[i].planes[0].plane_stride,
            io[i].planes[0].slice_height,
            io[i].offsets[0],
            (unsigned int)io[i].mem_handle[0],
            io[i].planes[0].packer_config,
            io[i].bpp);
    }

    armed = 0;

    pr_info(
        "cam-probe: probe complete\n");
}

static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    addr_prepare =
        kallsyms_lookup_name(
            "cam_ife_mgr_prepare_hw_update");

    pr_info(
        "cam-probe: prepare=%lx\n",
        addr_prepare);

    if (!addr_prepare)
        return -1;

    if (hook_wrap2(
        (void *)addr_prepare,
        before_prepare,
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

        armed = 1;

        pr_info(
            "cam-probe: armed\n");

        compat_copy_to_user(
            out_msg,
            "armed",
            6);

    } else if (args[0] == 's') {

        armed = 0;

        pr_info(
            "cam-probe: stopped\n");

        compat_copy_to_user(
            out_msg,
            "stopped",
            8);
    }

    return 0;
}

static long cam_kpm_exit(
    void *reserved)
{
    armed = 0;

    if (addr_prepare)
        unhook((void *)addr_prepare);

    pr_info(
        "cam-probe: exit\n");

    return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
