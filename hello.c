#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-preview-ubwc-dump");
KPM_VERSION("1.9.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Capture full dual-plane UBWC TP10 preview frame");

#define O_WRONLY 00000001
#define O_CREAT  00000100
#define O_TRUNC  00001000

#define CAM_BUF_OUTPUT 2
#define PREVIEW_RES 0x3000
#define PREVIEW_FMT 39

#define MAX_RES 32
#define MAX_PLANES 3
#define DYNAMIC_BUF_SIZE (16 * 1024 * 1024)

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

static void *(*p_filp_open)(const char *,int,unsigned int);
static long (*p_kernel_write)(void *,const void *,unsigned long,long long *);
static int (*p_filp_close)(void *,void *);
static void *(*p_vmalloc)(unsigned long);
static void (*p_vfree)(const void *);

static struct dma_buf *(*p_dma_buf_get)(int);
static void (*p_dma_buf_put)(struct dma_buf *);
static int (*p_dma_buf_begin_cpu_access)(struct dma_buf *,int);
static int (*p_dma_buf_end_cpu_access)(struct dma_buf *,int);
static void *(*p_dma_buf_vmap)(struct dma_buf *);
static void (*p_dma_buf_vunmap)(struct dma_buf *,void *);

static unsigned long addr_prepare,addr_buf_done;
static unsigned char *dyn_buf;

static volatile char capture_status;
static volatile unsigned int cnt_prepare,cnt_done;
static volatile unsigned int cnt_get,cnt_copy_ok,cnt_copy_fail;

static struct dma_buf *capture_dmabuf;
static volatile int capture_fd;
static volatile unsigned int capture_handle;
static volatile unsigned long long capture_request;

static volatile unsigned int capture_format;
static volatile unsigned int capture_width[2];
static volatile unsigned int capture_height[2];
static volatile unsigned int capture_stride[2];
static volatile unsigned int capture_slice[2];
static volatile unsigned int capture_offset[2];
static volatile unsigned int capture_meta_stride[2];
static volatile unsigned int capture_meta_size[2];

static volatile unsigned long cached_len;
static volatile unsigned long long cached_request;

static unsigned long align_up_4096(unsigned long x)
{
    return (x + 4095UL) & ~4095UL;
}

static int is_err_ptr(void *ptr)
{
    return (unsigned long)ptr >= (unsigned long)-4095;
}

static void release_capture_dmabuf(void)
{
    if (capture_dmabuf && p_dma_buf_put)
        p_dma_buf_put(capture_dmabuf);

    capture_dmabuf = NULL;
    capture_fd = -1;
    capture_handle = 0;
    capture_request = 0;
}

static void before_prepare(hook_fargs2_t *args,void *udata)
{
    struct kp_cam_packet *packet;
    struct kp_cam_buf_io_cfg *io;
    struct dma_buf *dmabuf;
    unsigned int i,n,handle;
    int fd;

    if (capture_status != 1 || capture_dmabuf)
        return;

    packet = *(struct kp_cam_packet **)args->arg1;
    if (!packet)
        return;

    if (!packet->num_io_configs ||
        packet->num_io_configs > 64)
        return;

    io = (struct kp_cam_buf_io_cfg *)(
        (unsigned char *)packet->payload +
        packet->io_configs_offset);

    for (i = 0; i < packet->num_io_configs; i++) {

        if (io[i].direction != CAM_BUF_OUTPUT)
            continue;

        if (io[i].resource_type != PREVIEW_RES)
            continue;

        if (io[i].format != PREVIEW_FMT)
            continue;

        if (!io[i].mem_handle[0])
            continue;

        handle = (unsigned int)io[i].mem_handle[0];
        fd = (int)(handle >> 16);

        dmabuf = p_dma_buf_get(fd);

        if (!dmabuf) {
            pr_info(
                "cam-preview: dma_buf_get FAILED fd=%d\n",
                fd);
            cnt_copy_fail++;
            return;
        }

        capture_dmabuf = dmabuf;
        capture_fd = fd;
        capture_handle = handle;
        capture_request = packet->header.request_id;
        capture_format = io[i].format;

        n = 0;

        for (i = 0; i < MAX_PLANES; i++) {

            if (!io[0].mem_handle[i])
                continue;

            capture_width[n] =
                io[0].planes[i].width;
            capture_height[n] =
                io[0].planes[i].height;
            capture_stride[n] =
                io[0].planes[i].plane_stride;
            capture_slice[n] =
                io[0].planes[i].slice_height;
            capture_offset[n] =
                io[0].offsets[i];
            capture_meta_stride[n] =
                io[0].planes[i].meta_stride;
            capture_meta_size[n] =
                io[0].planes[i].meta_size;

            pr_info(
                "cam-preview: plane[%u] "
                "w=%u h=%u stride=%u slice=%u "
                "offset=%u meta_stride=%u meta_size=%u\n",
                n,
                capture_width[n],
                capture_height[n],
                capture_stride[n],
                capture_slice[n],
                capture_offset[n],
                capture_meta_stride[n],
                capture_meta_size[n]);

            n++;

            if (n >= 2)
                break;
        }

        cnt_prepare++;

        pr_info(
            "cam-preview: PREP saved "
            "req=%llu fd=%d dmabuf=%p "
            "res=0x%x fmt=%u planes=%u\n",
            capture_request,
            capture_fd,
            capture_dmabuf,
            io[0].resource_type,
            capture_format,
            n);

        return;
    }
}

static void before_buf_done(hook_fargs2_t *args,void *udata)
{
    struct kp_cam_isp_hw_event_info *event_info;
    struct kp_cam_isp_hw_compdone_event_info *compdone;
    unsigned int i,n;

    if (capture_status != 1 || !capture_dmabuf)
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

    cnt_done++;

    for (i = 0; i < n; i++) {

        if (compdone->res_id[i] != PREVIEW_RES)
            continue;

        capture_status = 2;

        pr_info(
            "cam-preview: DONE hw=%u "
            "last_addr=0x%x req=%llu "
            "fd=%d dmabuf=%p\n",
            event_info->hw_idx,
            compdone->last_consumed_addr[i],
            capture_request,
            capture_fd,
            capture_dmabuf);

        return;
    }
}

static int capture_frame_from_control_context(void)
{
    void *vaddr;
    unsigned long p0_image,p0_total;
    unsigned long p1_image,p1_total;
    unsigned long total_len;
    int rc;

    if (!dyn_buf || !capture_dmabuf)
        return -1;

    if (!p_dma_buf_begin_cpu_access ||
        !p_dma_buf_end_cpu_access ||
        !p_dma_buf_vmap ||
        !p_dma_buf_vunmap)
        return -1;

    p0_image =
        align_up_4096(
            (unsigned long)capture_stride[0] *
            (unsigned long)capture_slice[0]);

    p0_total =
        (unsigned long)capture_meta_size[0] +
        p0_image;

    p1_image =
        align_up_4096(
            (unsigned long)capture_stride[1] *
            (unsigned long)capture_slice[1]);

    p1_total =
        (unsigned long)capture_meta_size[1] +
        p1_image;

    /*
     * Plane 1 的 offset 应该等于 plane 0 的结束位置。
     * 最终保存整个连续 DMA-BUF。
     */
    total_len =
        (unsigned long)capture_offset[1] +
        p1_total;

    if (!p0_total ||
        !p1_total ||
        !total_len ||
        total_len > DYNAMIC_BUF_SIZE) {

        pr_info(
            "cam-preview: invalid size "
            "p0=%lu p1=%lu total=%lu\n",
            p0_total,p1_total,total_len);

        cnt_copy_fail++;
        return -1;
    }

    pr_info(
        "cam-preview: GET "
        "p0=%lu p1=%lu total=%lu "
        "plane1_off=%u\n",
        p0_total,
        p1_total,
        total_len,
        capture_offset[1]);

    rc =
        p_dma_buf_begin_cpu_access(
            capture_dmabuf,0);

    if (rc) {
        pr_info(
            "cam-preview: begin_cpu rc=%d\n",
            rc);
        cnt_copy_fail++;
        return -1;
    }

    vaddr =
        p_dma_buf_vmap(
            capture_dmabuf);

    if (!vaddr) {

        pr_info(
            "cam-preview: vmap failed\n");

        p_dma_buf_end_cpu_access(
            capture_dmabuf,0);

        cnt_copy_fail++;
        return -1;
    }

    pr_info(
        "cam-preview: COPY source=%lx "
        "total=%lu\n",
        (unsigned long)vaddr,
        total_len);

    memcpy(
        dyn_buf,
        (unsigned char *)vaddr,
        total_len);

    p_dma_buf_vunmap(
        capture_dmabuf,
        vaddr);

    p_dma_buf_end_cpu_access(
        capture_dmabuf,0);

    cached_len = total_len;
    cached_request = capture_request;

    cnt_get++;
    cnt_copy_ok++;

    capture_status = 3;

    pr_info(
        "cam-preview: CAPTURE OK "
        "req=%llu fd=%d len=%lu "
        "p0=%lu p1=%lu "
        "w=%u h=%u format=%u\n",
        cached_request,
        capture_fd,
        cached_len,
        p0_total,
        p1_total,
        capture_width[0],
        capture_height[0],
        capture_format);

    return 0;
}

static int write_cached_frame_to_disk(void)
{
    void *file;
    long long pos = 0;
    long written;

    if (!dyn_buf || !cached_len)
        return -1;

    file =
        p_filp_open(
            "/data/local/tmp/preview.ubwc",
            O_CREAT | O_WRONLY | O_TRUNC,
            0644);

    if (is_err_ptr(file)) {
        pr_err(
            "cam-preview: open preview.ubwc failed\n");
        return -1;
    }

    written =
        p_kernel_write(
            file,
            dyn_buf,
            cached_len,
            &pos);

    p_filp_close(
        file,
        NULL);

    pr_info(
        "cam-preview: written=%ld "
        "expected=%lu\n",
        written,
        cached_len);

    if (written !=
        (long)cached_len)
        return -1;

    capture_status = 4;

    return 0;
}

static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    p_filp_open =
        (void *)kallsyms_lookup_name("filp_open");

    p_kernel_write =
        (void *)kallsyms_lookup_name("kernel_write");

    p_filp_close =
        (void *)kallsyms_lookup_name("filp_close");

    p_vmalloc =
        (void *)kallsyms_lookup_name("vmalloc");

    p_vfree =
        (void *)kallsyms_lookup_name("vfree");

    p_dma_buf_get =
        (void *)kallsyms_lookup_name("dma_buf_get");

    p_dma_buf_put =
        (void *)kallsyms_lookup_name("dma_buf_put");

    p_dma_buf_begin_cpu_access =
        (void *)kallsyms_lookup_name("dma_buf_begin_cpu_access");

    p_dma_buf_end_cpu_access =
        (void *)kallsyms_lookup_name("dma_buf_end_cpu_access");

    p_dma_buf_vmap =
        (void *)kallsyms_lookup_name("dma_buf_vmap");

    p_dma_buf_vunmap =
        (void *)kallsyms_lookup_name("dma_buf_vunmap");

    addr_prepare =
        kallsyms_lookup_name(
            "cam_ife_mgr_prepare_hw_update");

    addr_buf_done =
        kallsyms_lookup_name(
            "cam_ife_hw_mgr_handle_hw_buf_done");

    pr_info(
        "cam-preview: prepare=%lx "
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

    if (!p_filp_open ||
        !p_kernel_write ||
        !p_filp_close ||
        !p_vmalloc ||
        !p_vfree ||
        !p_dma_buf_get ||
        !p_dma_buf_put ||
        !p_dma_buf_begin_cpu_access ||
        !p_dma_buf_end_cpu_access ||
        !p_dma_buf_vmap ||
        !p_dma_buf_vunmap ||
        !addr_prepare ||
        !addr_buf_done)
        return -1;

    dyn_buf =
        p_vmalloc(DYNAMIC_BUF_SIZE);

    if (!dyn_buf)
        return -1;

    pr_info(
        "cam-preview: dyn_buf=%p "
        "size=%d\n",
        dyn_buf,
        DYNAMIC_BUF_SIZE);

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

        release_capture_dmabuf();

        capture_status = 1;
        cached_len = 0;
        cached_request = 0;

        cnt_prepare = 0;
        cnt_done = 0;
        cnt_get = 0;
        cnt_copy_ok = 0;
        cnt_copy_fail = 0;

        pr_info(
            "cam-preview: armed\n");

        compat_copy_to_user(
            out_msg,"armed",6);

    } else if (args[0] == 'g') {

        if (capture_status != 2) {

            pr_info(
                "cam-preview: "
                "no preview DONE\n");

            compat_copy_to_user(
                out_msg,
                "no_done",
                8);

            return 0;
        }

        if (capture_frame_from_control_context() == 0)

            compat_copy_to_user(
                out_msg,
                "capture_ok",
                11);

        else

            compat_copy_to_user(
                out_msg,
                "capture_fail",
                13);

    } else if (args[0] == 'w') {

        if (capture_status != 3 ||
            !cached_len) {

            pr_info(
                "cam-preview: "
                "no captured frame\n");

            compat_copy_to_user(
                out_msg,
                "no_frame",
                9);

            return 0;
        }

        if (write_cached_frame_to_disk() == 0)

            compat_copy_to_user(
                out_msg,
                "write_ok",
                9);

        else

            compat_copy_to_user(
                out_msg,
                "write_fail",
                11);

    } else if (args[0] == 's') {

        capture_status = 0;

        pr_info(
            "cam-preview: STOP "
            "prepare=%u done=%u get=%u "
            "copy_ok=%u copy_fail=%u "
            "len=%lu req=%llu fd=%d "
            "dmabuf=%p\n",
            cnt_prepare,
            cnt_done,
            cnt_get,
            cnt_copy_ok,
            cnt_copy_fail,
            cached_len,
            cached_request,
            capture_fd,
            capture_dmabuf);

        release_capture_dmabuf();

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
    capture_status = 0;

    if (addr_buf_done)
        unhook(
            (void *)addr_buf_done);

    if (addr_prepare)
        unhook(
            (void *)addr_prepare);

    release_capture_dmabuf();

    if (dyn_buf && p_vfree)
        p_vfree(dyn_buf);

    dyn_buf = NULL;

    pr_info(
        "cam-preview: exit\n");

    return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
