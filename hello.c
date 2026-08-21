#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-ubwc-config-probe");
KPM_VERSION("2.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Probe runtime UBWC CONFIG V2 from generic blob");

#define META_GENERIC_BLOB 12
#define UBWC_CONFIG_V2    6
#define MAX_CMD           32
#define MAX_PORT          16
#define MAX_PLANE         2

#define BLOB_TYPE_MASK    0xFF
#define BLOB_SIZE_SHIFT   8
#define BLOB_SIZE_MASK    0xFFFFFF00

struct kp_cam_packet_header {
    unsigned int op_code,size;
    unsigned long long request_id;
    unsigned int flags,padding;
};

struct kp_cam_cmd_buf_desc {
    int mem_handle;
    unsigned int offset,size,length,type,meta_data;
};

struct kp_cam_packet {
    struct kp_cam_packet_header header;
    unsigned int cmd_buf_offset,num_cmd_buf;
    unsigned int io_configs_offset,num_io_configs;
    unsigned int patch_offset,num_patches;
    unsigned int kmd_cmd_buf_index,kmd_cmd_buf_offset;
    unsigned long long payload[1];
};

struct kp_ubwc_plane {
    unsigned int port_type;
    unsigned int meta_stride;
    unsigned int meta_size;
    unsigned int meta_offset;
    unsigned int packer_config;
    unsigned int mode_config_0;
    unsigned int mode_config_1;
    unsigned int tile_config;
    unsigned int h_init;
    unsigned int v_init;
    unsigned int static_ctrl;
    unsigned int ctrl_2;
    unsigned int stats_ctrl_2;
    unsigned int lossy_threshold_0;
    unsigned int lossy_threshold_1;
    unsigned int lossy_var_offset;
    unsigned int bandwidth_limit;
    unsigned int reserved[3];
};

struct kp_ubwc_config_v2 {
    unsigned int api_version;
    unsigned int num_ports;
    struct kp_ubwc_plane ubwc_plane_cfg[1][MAX_PLANE];
};

static unsigned long addr_prepare;
static int (*p_cam_mem_get_cpu_buf)(
    int, unsigned long *, unsigned long *);
static volatile int armed;

static void dump_ubwc(
    unsigned char *data,
    unsigned int size)
{
    struct kp_ubwc_config_v2 *cfg;
    struct kp_ubwc_plane *p;
    unsigned int i,j,n,need;

    if (size < 8)
        return;

    cfg = (struct kp_ubwc_config_v2 *)data;
    n = cfg->num_ports;

    if (!n || n > MAX_PORT) {
        pr_info(
            "cam-ubwc: invalid num_ports=%u\n",n);
        return;
    }

    need = 8 + n *
        sizeof(struct kp_ubwc_plane) *
        MAX_PLANE;

    if (size < need) {
        pr_info(
            "cam-ubwc: blob too small "
            "size=%u need=%u ports=%u\n",
            size,need,n);
        return;
    }

    pr_info(
        "cam-ubwc: CONFIG_V2 "
        "api=%u ports=%u size=%u\n",
        cfg->api_version,n,size);

    for (i = 0; i < n; i++) {
        for (j = 0; j < MAX_PLANE; j++) {

            p = &cfg->ubwc_plane_cfg[i][j];

            pr_info(
                "cam-ubwc: P[%u][%u] "
                "port=0x%x meta_stride=%u "
                "meta_size=%u meta_off=%u\n",
                i,j,
                p->port_type,
                p->meta_stride,
                p->meta_size,
                p->meta_offset);

            pr_info(
                "cam-ubwc: P[%u][%u] "
                "pack=0x%x mode0=0x%x "
                "mode1=0x%x tile=0x%x\n",
                i,j,
                p->packer_config,
                p->mode_config_0,
                p->mode_config_1,
                p->tile_config);

            pr_info(
                "cam-ubwc: P[%u][%u] "
                "h=%u v=%u static=0x%x "
                "ctrl2=0x%x stats2=0x%x\n",
                i,j,
                p->h_init,
                p->v_init,
                p->static_ctrl,
                p->ctrl_2,
                p->stats_ctrl_2);

            pr_info(
                "cam-ubwc: P[%u][%u] "
                "lossy0=0x%x lossy1=0x%x "
                "var=0x%x bw=0x%x\n",
                i,j,
                p->lossy_threshold_0,
                p->lossy_threshold_1,
                p->lossy_var_offset,
                p->bandwidth_limit);
        }
    }
}

static void scan_cmd(
    struct kp_cam_cmd_buf_desc *d)
{
    unsigned long cpu_addr=0,buf_size=0;
    unsigned char *ptr;
    unsigned int pos=0,type,size,block;
    int rc;

    if (!d->length || !d->size)
        return;

    rc = p_cam_mem_get_cpu_buf(
        d->mem_handle,
        &cpu_addr,
        &buf_size);

    if (rc || !cpu_addr || !buf_size) {
        pr_info(
            "cam-ubwc: get_cpu_buf "
            "handle=%d rc=%d\n",
            d->mem_handle,rc);
        return;
    }

    if ((unsigned long)d->offset >= buf_size ||
        (unsigned long)d->offset + d->length > buf_size) {
        pr_info(
            "cam-ubwc: invalid cmd range "
            "off=%u len=%u buf=%lu\n",
            d->offset,d->length,buf_size);
        return;
    }

    ptr = (unsigned char *)cpu_addr + d->offset;

    while (pos + 4 <= d->length) {

        type =
            (*(unsigned int *)(ptr + pos) &
             BLOB_TYPE_MASK);

        size =
            (*(unsigned int *)(ptr + pos) &
             BLOB_SIZE_MASK) >>
             BLOB_SIZE_SHIFT;

        block =
            4 + ((size + 3) & ~3U);

        if (!block ||
            pos + block > d->length)
            break;

        pr_info(
            "cam-ubwc: blob "
            "type=%u size=%u pos=%u\n",
            type,size,pos);

        if (type == UBWC_CONFIG_V2) {
            dump_ubwc(
                ptr + pos + 4,
                size);
            return;
        }

        pos += block;
    }
}

static void before_prepare(
    hook_fargs2_t *args,
    void *udata)
{
    struct kp_cam_packet *p;
    struct kp_cam_cmd_buf_desc *cmd;
    unsigned int i;

    if (!armed)
        return;

    p = *(struct kp_cam_packet **)args->arg1;

    if (!p ||
        !p->num_cmd_buf ||
        p->num_cmd_buf > MAX_CMD)
        return;

    cmd = (struct kp_cam_cmd_buf_desc *)(
        (unsigned char *)p->payload +
        p->cmd_buf_offset);

    pr_info(
        "cam-ubwc: PREP req=%llu "
        "cmds=%u\n",
        p->header.request_id,
        p->num_cmd_buf);

    for (i = 0; i < p->num_cmd_buf; i++) {

        if (cmd[i].meta_data !=
            META_GENERIC_BLOB)
            continue;

        pr_info(
            "cam-ubwc: CMD[%u] "
            "handle=%d off=%u len=%u "
            "size=%u meta=%u\n",
            i,
            cmd[i].mem_handle,
            cmd[i].offset,
            cmd[i].length,
            cmd[i].size,
            cmd[i].meta_data);

        scan_cmd(&cmd[i]);
    }

    armed = 0;

    pr_info(
        "cam-ubwc: probe complete\n");
}

static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    addr_prepare =
        kallsyms_lookup_name(
            "cam_ife_mgr_prepare_hw_update");

    p_cam_mem_get_cpu_buf =
        (void *)kallsyms_lookup_name(
            "cam_mem_get_cpu_buf");

    pr_info(
        "cam-ubwc: prepare=%lx "
        "get_cpu_buf=%lx\n",
        addr_prepare,
        (unsigned long)p_cam_mem_get_cpu_buf);

    if (!addr_prepare ||
        !p_cam_mem_get_cpu_buf)
        return -1;

    if (hook_wrap2(
        (void *)addr_prepare,
        before_prepare,
        NULL,NULL))
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
            out_msg,"armed",6);

    } else if (args[0] == 's') {
        armed = 0;

        pr_info(
            "cam-ubwc: stopped\n");

        compat_copy_to_user(
            out_msg,"stopped",8);
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
