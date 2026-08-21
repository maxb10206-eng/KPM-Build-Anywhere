#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-preview-plane-probe");
KPM_VERSION("1.9.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Probe UBWC TP10 preview planes");

#define CAM_BUF_OUTPUT 2
#define PREVIEW_RES 0x3000
#define PREVIEW_FMT 39
#define MAX_RES 32
#define MAX_PLANES 3

struct dma_buf;

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

struct kp_cam_isp_hw_event_info {
    unsigned int res_type;
    unsigned char is_secondary_evt;
    unsigned char reserved[3];
    unsigned int res_id,hw_idx,reg_val,hw_type,in_core_idx;
    void *event_data;
};

struct kp_cam_isp_hw_compdone_event_info {
    unsigned int num_res;
    unsigned int res_id[MAX_RES];
    unsigned int last_consumed_addr[MAX_RES];
};

static struct dma_buf *(*p_dma_buf_get)(int);
static void (*p_dma_buf_put)(struct dma_buf *);
static int (*p_dma_buf_begin_cpu_access)(struct dma_buf *,int);
static int (*p_dma_buf_end_cpu_access)(struct dma_buf *,int);
static void *(*p_dma_buf_vmap)(struct dma_buf *);
static void (*p_dma_buf_vunmap)(struct dma_buf *,void *);

static unsigned long addr_prepare,addr_buf_done;
static volatile int armed,done_seen;

static struct dma_buf *saved_dmabuf[MAX_PLANES];
static volatile int saved_fd[MAX_PLANES];

static volatile unsigned int saved_handle[MAX_PLANES];
static volatile unsigned int saved_offset[MAX_PLANES];
static volatile unsigned int saved_width[MAX_PLANES];
static volatile unsigned int saved_height[MAX_PLANES];
static volatile unsigned int saved_stride[MAX_PLANES];
static volatile unsigned int saved_slice[MAX_PLANES];
static volatile unsigned int saved_meta_stride[MAX_PLANES];
static volatile unsigned int saved_meta_size[MAX_PLANES];
static volatile unsigned int saved_format;
static volatile unsigned long long saved_request;

static void release_dmabufs(void)
{
    unsigned int i;

    for (i = 0; i < MAX_PLANES; i++) {
        if (saved_dmabuf[i] && p_dma_buf_put)
            p_dma_buf_put(saved_dmabuf[i]);

        saved_dmabuf[i] = NULL;
        saved_fd[i] = -1;
        saved_handle[i] = 0;
    }
}

static void before_prepare(hook_fargs2_t *args,void *udata)
{
    struct kp_cam_packet *p;
    struct kp_cam_buf_io_cfg *io;
    struct kp_cam_plane_cfg *pl;
    struct dma_buf *dmabuf;
    unsigned int i,handle;
    int fd;

    if (!armed)
        return;

    if (saved_dmabuf[0] ||
        saved_dmabuf[1] ||
        saved_dmabuf[2])
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

    for (i = 0; i < p->num_io_configs; i++) {

        if (io[i].direction != CAM_BUF_OUTPUT)
            continue;

        if (io[i].resource_type != PREVIEW_RES)
            continue;

        if (io[i].format != PREVIEW_FMT)
            continue;

        saved_format = io[i].format;
        saved_request = p->header.request_id;

        pr_info(
            "cam-plane: PREP req=%llu res=0x%x fmt=%u\n",
            saved_request,
            io[i].resource_type,
            saved_format);

        for (i = 0; i < MAX_PLANES; i++) {

            pl = &io[0].planes[i];

            if (!io[0].mem_handle[i]) {
                pr_info(
                    "cam-plane: plane[%u] EMPTY\n",
                    i);
                continue;
            }

            handle =
                (unsigned int)io[0].mem_handle[i];

            fd = (int)(handle >> 16);

            dmabuf = p_dma_buf_get(fd);

            if (!dmabuf) {
                pr_info(
                    "cam-plane: plane[%u] "
                    "dma_buf_get FAILED fd=%d\n",
                    i,fd);
                continue;
            }

            saved_dmabuf[i] = dmabuf;
            saved_fd[i] = fd;
            saved_handle[i] = handle;
            saved_offset[i] = io[0].offsets[i];
            saved_width[i] = pl->width;
            saved_height[i] = pl->height;
            saved_stride[i] = pl->plane_stride;
            saved_slice[i] = pl->slice_height;
            saved_meta_stride[i] = pl->meta_stride;
            saved_meta_size[i] = pl->meta_size;

            pr_info(
                "cam-plane: plane[%u] "
                "fd=%d handle=0x%x "
                "w=%u h=%u stride=%u slice=%u "
                "offset=%u meta_stride=%u "
                "meta_size=%u\n",
                i,
                fd,
                handle,
                pl->width,
                pl->height,
                pl->plane_stride,
                pl->slice_height,
                io[0].offsets[i],
                pl->meta_stride,
                pl->meta_size);
        }

        return;
    }
}

static void before_buf_done(hook_fargs2_t *args,void *udata)
{
    struct kp_cam_isp_hw_event_info *event_info;
    struct kp_cam_isp_hw_compdone_event_info *compdone;
    unsigned int i,n;

    if (!armed)
        return;

    if (!saved_dmabuf[0] &&
        !saved_dmabuf[1] &&
        !saved_dmabuf[2])
        return;

    event_info =
        (struct kp_cam_isp_hw_event_info *)args->arg1;

    if (!event_info ||
        !event_info->event_data)
        return;

    compdone =
        (struct kp_cam_isp_hw_compdone_event_info *)
        event_info->event_data;

    n = compdone->num_res;

    if (n > MAX_RES)
        n = MAX_RES;

    for (i = 0; i < n; i++) {

        if (compdone->res_id[i] != PREVIEW_RES)
            continue;

        done_seen = 1;

        pr_info(
            "cam-plane: DONE hw=%u req=%llu\n",
            event_info->hw_idx,
            saved_request);

        return;
    }
}

static void probe_plane(unsigned int n)
{
    unsigned char *vaddr;
    unsigned char data[16];
    int rc,i;

    if (!saved_dmabuf[n]) {
        pr_info(
            "cam-plane: plane[%u] no dmabuf\n",
            n);
        return;
    }

    pr_info(
        "cam-plane: plane[%u] BEGIN "
        "fd=%d offset=%u\n",
        n,
        saved_fd[n],
        saved_offset[n]);

    rc = p_dma_buf_begin_cpu_access(
        saved_dmabuf[n],0);

    pr_info(
        "cam-plane: plane[%u] "
        "begin_cpu rc=%d\n",
        n,rc);

    if (rc)
        return;

    vaddr =
        p_dma_buf_vmap(
            saved_dmabuf[n]);

    pr_info(
        "cam-plane: plane[%u] vmap=%lx\n",
        n,
        (unsigned long)vaddr);

    if (!vaddr) {
        p_dma_buf_end_cpu_access(
            saved_dmabuf[n],0);
        return;
    }

    memcpy(
        data,
        vaddr + saved_offset[n],
        sizeof(data));

    pr_info(
        "cam-plane: plane[%u] DATA "
        "%02x %02x %02x %02x "
        "%02x %02x %02x %02x "
        "%02x %02x %02x %02x "
        "%02x %02x %02x %02x\n",
        n,
        data[0],data[1],data[2],data[3],
        data[4],data[5],data[6],data[7],
        data[8],data[9],data[10],data[11],
        data[12],data[13],data[14],data[15]);

    p_dma_buf_vunmap(
        saved_dmabuf[n],
        vaddr);

    pr_info(
        "cam-plane: plane[%u] vunmap ok\n",
        n);

    rc =
        p_dma_buf_end_cpu_access(
            saved_dmabuf[n],0);

    pr_info(
        "cam-plane: plane[%u] "
        "end_cpu rc=%d\n",
        n,rc);

    if (!rc)
        pr_info(
            "cam-plane: plane[%u] READ OK\n",
            n);

    for (i = 0; i < 1; i++)
        ;
}

static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    p_dma_buf_get =
        (void *)kallsyms_lookup_name(
            "dma_buf_get");

    p_dma_buf_put =
        (void *)kallsyms_lookup_name(
            "dma_buf_put");

    p_dma_buf_begin_cpu_access =
        (void *)kallsyms_lookup_name(
            "dma_buf_begin_cpu_access");

    p_dma_buf_end_cpu_access =
        (void *)kallsyms_lookup_name(
            "dma_buf_end_cpu_access");

    p_dma_buf_vmap =
        (void *)kallsyms_lookup_name(
            "dma_buf_vmap");

    p_dma_buf_vunmap =
        (void *)kallsyms_lookup_name(
            "dma_buf_vunmap");

    addr_prepare =
        kallsyms_lookup_name(
            "cam_ife_mgr_prepare_hw_update");

    addr_buf_done =
        kallsyms_lookup_name(
            "cam_ife_hw_mgr_handle_hw_buf_done");

    pr_info(
        "cam-plane: prepare=%lx "
        "buf_done=%lx get=%lx "
        "begin=%lx end=%lx "
        "vmap=%lx vunmap=%lx\n",
        addr_prepare,
        addr_buf_done,
        (unsigned long)p_dma_buf_get,
        (unsigned long)p_dma_buf_begin_cpu_access,
        (unsigned long)p_dma_buf_end_cpu_access,
        (unsigned long)p_dma_buf_vmap,
        (unsigned long)p_dma_buf_vunmap);

    if (!addr_prepare ||
        !addr_buf_done ||
        !p_dma_buf_get ||
        !p_dma_buf_put ||
        !p_dma_buf_begin_cpu_access ||
        !p_dma_buf_end_cpu_access ||
        !p_dma_buf_vmap ||
        !p_dma_buf_vunmap)
        return -1;

    if (hook_wrap2(
            (void *)addr_prepare,
            before_prepare,
            NULL,NULL))
        return -1;

    if (hook_wrap2(
            (void *)addr_buf_done,
            before_buf_done,
            NULL,NULL)) {

        unhook(
            (void *)addr_prepare);

        return -1;
    }

    pr_info(
        "cam-plane: init ok\n");

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

        release_dmabufs();

        armed = 1;
        done_seen = 0;

        pr_info(
            "cam-plane: armed\n");

        compat_copy_to_user(
            out_msg,
            "armed",
            6);

    } else if (args[0] == 'g') {

        if (!done_seen) {

            pr_info(
                "cam-plane: no preview DONE\n");

            compat_copy_to_user(
                out_msg,
                "no_done",
                8);

            return 0;
        }

        pr_info(
            "cam-plane: probing planes\n");

        probe_plane(0);
        probe_plane(1);
        probe_plane(2);

        compat_copy_to_user(
            out_msg,
            "probe_ok",
            9);

    } else if (args[0] == 's') {

        armed = 0;

        pr_info(
            "cam-plane: stop\n");

        release_dmabufs();

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

    if (addr_buf_done)
        unhook(
            (void *)addr_buf_done);

    if (addr_prepare)
        unhook(
            (void *)addr_prepare);

    release_dmabufs();

    pr_info(
        "cam-plane: exit\n");

    return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
