#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-ubwc-config-probe");
KPM_VERSION("2.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Probe Camera PREP packet for UBWC config");

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

struct kp_cam_cmd_buf_desc {
    int mem_handle;
    unsigned int offset,size,length,type,meta_data;
};

static unsigned long addr_prepare;
static volatile int armed;

static void before_prepare(
    hook_fargs2_t *args,void *udata)
{
    struct kp_cam_packet *p;
    struct kp_cam_cmd_buf_desc *cmd;
    unsigned int i,n;

    if (!armed)
        return;

    p = *(struct kp_cam_packet **)args->arg1;
    if (!p)
        return;

    pr_info(
        "cam-ubwc: PREP req=%llu "
        "op=0x%x size=%u "
        "cmd_off=%u cmd_num=%u "
        "io_off=%u io_num=%u "
        "patch_off=%u patch_num=%u\n",
        p->header.request_id,
        p->header.op_code,
        p->header.size,
        p->cmd_buf_offset,
        p->num_cmd_buf,
        p->io_configs_offset,
        p->num_io_configs,
        p->patch_offset,
        p->num_patches);

    n = p->num_cmd_buf;
    if (n > 32)
        n = 32;

    cmd = (struct kp_cam_cmd_buf_desc *)(
        (unsigned char *)p->payload +
        p->cmd_buf_offset);

    for (i = 0; i < n; i++) {
        pr_info(
            "cam-ubwc: CMD[%u] "
            "mem=%d off=%u size=%u "
            "len=%u type=%u meta=%u\n",
            i,
            cmd[i].mem_handle,
            cmd[i].offset,
            cmd[i].size,
            cmd[i].length,
            cmd[i].type,
            cmd[i].meta_data);
    }

    armed = 0;

    pr_info(
        "cam-ubwc: PREP dump complete\n");
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
        "cam-ubwc: prepare=%lx\n",
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
        "cam-ubwc: init ok\n");

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
            "cam-ubwc: armed\n");

        compat_copy_to_user(
            out_msg,
            "armed",
            6);

    } else if (args[0] == 's') {
        armed = 0;

        pr_info(
            "cam-ubwc: stopped\n");

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
        "cam-ubwc: exit\n");

    return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
