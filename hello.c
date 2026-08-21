#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-preview-ubwc-probe");
KPM_VERSION("1.8.3");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Probe preview UBWC TP10 layout");

#define CAM_BUF_OUTPUT 2
#define PREVIEW_RES 0x3000
#define PREVIEW_FMT 39
#define MAX_RES 32
#define TEST_READ_LEN 64

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
static struct dma_buf *saved_dmabuf;

static volatile int saved_fd;
static volatile unsigned int saved_handle;
static volatile unsigned long long saved_request;
static volatile unsigned int saved_width,saved_height;
static volatile unsigned int saved_stride,saved_slice;
static volatile unsigned int saved_offset,saved_format;

static void release_dmabuf(void)
{
    if (saved_dmabuf && p_dma_buf_put)
        p_dma_buf_put(saved_dmabuf);

    saved_dmabuf = NULL;
    saved_fd = -1;
    saved_handle = 0;
    saved_request = 0;
}

static void before_prepare(hook_fargs2_t *args,void *udata)
{
    struct kp_cam_packet *p;
    struct kp_cam_buf_io_cfg *io;
    struct kp_cam_plane_cfg *pl;
    struct dma_buf *dmabuf;
    unsigned int i,handle;
    int fd;

    if (!armed || saved_dmabuf)
        return;

    p = *(struct kp_cam_packet **)args->arg1;
    if (!p || !p->num_io_configs || p->num_io_configs > 64)
        return;

    io = (struct kp_cam_buf_io_cfg *)(
        (unsigned char *)p->payload + p->io_configs_offset);

    for (i = 0; i < p->num_io_configs; i++) {
        if (io[i].direction != CAM_BUF_OUTPUT)
            continue;
        if (io[i].resource_type != PREVIEW_RES)
            continue;
        if (io[i].format != PREVIEW_FMT)
            continue;
        if (!io[i].mem_handle[0])
            continue;

        pl = &io[i].planes[0];

        handle = (unsigned int)io[i].mem_handle[0];
        fd = (int)(handle >> 16);

        dmabuf = p_dma_buf_get(fd);
        if (!dmabuf) {
            pr_info(
                "cam-preview: dma_buf_get FAILED fd=%d\n",
                fd);
            return;
        }

        saved_dmabuf = dmabuf;
        saved_fd = fd;
        saved_handle = handle;
        saved_request = p->header.request_id;
        saved_width = pl->width;
        saved_height = pl->height;
        saved_stride = pl->plane_stride;
        saved_slice = pl->slice_height;
        saved_offset = io[i].offsets[0];
        saved_format = io[i].format;

        pr_info(
            "cam-preview: PREP req=%llu fd=%d dmabuf=%p "
            "res=0x%x fmt=%u\n",
            saved_request,
            saved_fd,
            saved_dmabuf,
            io[i].resource_type,
            saved_format);

        pr_info(
            "cam-preview: GEOM "
            "w=%u h=%u stride=%u slice=%u off=%u "
            "main_bytes=%llu\n",
            pl->width,
            pl->height,
            pl->plane_stride,
            pl->slice_height,
            io[i].offsets[0],
            (unsigned long long)pl->plane_stride *
            (unsigned long long)pl->slice_height);

        pr_info(
            "cam-preview: META "
            "stride=%u size=%u off=%u\n",
            pl->meta_stride,
            pl->meta_size,
            pl->meta_offset);

        pr_info(
            "cam-preview: CFG "
            "packer=0x%x mode=0x%x tile=0x%x "
            "h_init=%u v_init=%u\n",
            pl->packer_config,
            pl->mode_config,
            pl->tile_config,
            pl->h_init,
            pl->v_init);

        return;
    }
}

static void before_buf_done(hook_fargs2_t *args,void *udata)
{
    struct kp_cam_isp_hw_event_info *event_info;
    struct kp_cam_isp_hw_compdone_event_info *compdone;
    unsigned int i,n;

    if (!armed || !saved_dmabuf || done_seen)
        return;

    event_info =
        (struct kp_cam_isp_hw_event_info *)args->arg1;

    if (!event_info || !event_info->event_data)
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
            "cam-preview: DONE hw=%u req=%llu "
            "fd=%d last_addr=0x%x\n",
            event_info->hw_idx,
            saved_request,
            saved_fd,
            compdone->last_consumed_addr[i]);

        return;
    }
}

static int read_preview64(void)
{
    unsigned char *vaddr;
    unsigned char data[TEST_READ_LEN];
    unsigned long long main_bytes;
    int rc,i;

    if (!saved_dmabuf || !done_seen)
        return -1;

    main_bytes =
        (unsigned long long)saved_stride *
        (unsigned long long)saved_slice;

    pr_info(
        "cam-preview: geometry bytes=%llu "
        "w=%u h=%u stride=%u slice=%u offset=%u\n",
        main_bytes,
        saved_width,
        saved_height,
        saved_stride,
        saved_slice,
        saved_offset);

    rc = p_dma_buf_begin_cpu_access(
        saved_dmabuf,0);

    pr_info(
        "cam-preview: begin_cpu rc=%d\n",
        rc);

    if (rc)
        return rc;

    vaddr = p_dma_buf_vmap(saved_dmabuf);

    pr_info(
        "cam-preview: vmap=%lx\n",
        (unsigned long)vaddr);

    if (!vaddr) {
        p_dma_buf_end_cpu_access(
            saved_dmabuf,0);
        return -1;
    }

    memcpy(
        data,
        vaddr + saved_offset,
        TEST_READ_LEN);

    pr_info(
        "cam-preview: DATA 00: "
        "%02x %02x %02x %02x %02x %02x %02x %02x "
        "%02x %02x %02x %02x %02x %02x %02x %02x\n",
        data[0],data[1],data[2],data[3],
        data[4],data[5],data[6],data[7],
        data[8],data[9],data[10],data[11],
        data[12],data[13],data[14],data[15]);

    for (i = 16; i < TEST_READ_LEN; i += 16) {
        pr_info(
            "cam-preview: DATA %02d: "
            "%02x %02x %02x %02x %02x %02x %02x %02x "
            "%02x %02x %02x %02x %02x %02x %02x %02x\n",
            i,
            data[i],data[i+1],data[i+2],data[i+3],
            data[i+4],data[i+5],data[i+6],data[i+7],
            data[i+8],data[i+9],data[i+10],data[i+11],
            data[i+12],data[i+13],data[i+14],data[i+15]);
    }

    p_dma_buf_vunmap(
        saved_dmabuf,vaddr);

    pr_info(
        "cam-preview: vunmap ok\n");

    rc = p_dma_buf_end_cpu_access(
        saved_dmabuf,0);

    pr_info(
        "cam-preview: end_cpu rc=%d\n",
        rc);

    if (!rc)
        pr_info(
            "cam-preview: READ64 OK\n");

    return rc;
}

static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    addr_prepare =
        kallsyms_lookup_name(
            "cam_ife_mgr_prepare_hw_update");

    addr_buf_done =
        kallsyms_lookup_name(
            "cam_ife_hw_mgr_handle_hw_buf_done");

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

    pr_info(
        "cam-preview: prepare=%lx buf_done=%lx "
        "get=%lx begin=%lx end=%lx "
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
        unhook((void *)addr_prepare);
        return -1;
    }

    pr_info(
        "cam-preview: init ok\n");

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

        release_dmabuf();

        armed = 1;
        done_seen = 0;

        saved_fd = -1;
        saved_handle = 0;
        saved_request = 0;

        pr_info(
            "cam-preview: armed\n");

        compat_copy_to_user(
            out_msg,"armed",6);

    } else if (args[0] == 'g') {

        if (!saved_dmabuf || !done_seen) {
            pr_info(
                "cam-preview: no preview DONE\n");

            compat_copy_to_user(
                out_msg,"no_done",8);

            return 0;
        }

        if (!read_preview64())
            compat_copy_to_user(
                out_msg,"read_ok",8);
        else
            compat_copy_to_user(
                out_msg,"read_fail",10);

    } else if (args[0] == 's') {

        armed = 0;

        pr_info(
            "cam-preview: stop fd=%d dmabuf=%p\n",
            saved_fd,
            saved_dmabuf);

        release_dmabuf();

        compat_copy_to_user(
            out_msg,"stopped",8);
    }

    return 0;
}

static long cam_kpm_exit(void *reserved)
{
    armed = 0;

    if (addr_buf_done)
        unhook((void *)addr_buf_done);

    if (addr_prepare)
        unhook((void *)addr_prepare);

    release_dmabuf();

    pr_info(
        "cam-preview: exit\n");

    return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
