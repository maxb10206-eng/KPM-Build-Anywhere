#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/minmax.h>
#include <linux/types.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-ubwc-frame-injector");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Inject sequential TP10 frames into CAM_BUF_INPUT before VFE Read");

#define CAM_BUF_INPUT        1
#define CAM_FORMAT_TP10      33

#define MAX_IO_CFG           32
#define MAX_PLANES           2
#define MAX_FILE_SIZE        (128UL * 1024UL * 1024UL)

#define INJECT_DISABLED      0
#define INJECT_ONCE          1
#define INJECT_LOOP          2

/*
 * These match the camera-kernel UAPI definitions
 * we inspected earlier.
 */

struct kp_cam_plane_cfg {
    unsigned int width;
    unsigned int height;
    unsigned int plane_stride;
    unsigned int slice_height;
    unsigned int meta_stride;
    unsigned int meta_size;
    unsigned int meta_offset;
    unsigned int packer_config;
    unsigned int mode_config;
    unsigned int tile_config;
    unsigned int h_init;
    unsigned int v_init;
};

struct kp_cam_buf_io_cfg {
    int mem_handle[MAX_PLANES];
    unsigned int offsets[MAX_PLANES];

    struct kp_cam_plane_cfg planes[MAX_PLANES];

    unsigned int format;
    unsigned int color_space;
    unsigned int color_pattern;
    unsigned int bpp;
    unsigned int rotation;
    unsigned int resource_type;

    int fence;
    int early_fence;

    unsigned long long aux_cmd_buf[8];

    unsigned int direction;
    unsigned int batch_size;
    unsigned int subsample_pattern;
    unsigned int subsample_period;
    unsigned int framedrop_pattern;
    unsigned int framedrop_period;
    unsigned int flag;
    unsigned int padding;
};

struct kp_cam_packet_header {
    unsigned int op_code;
    unsigned int size;
    unsigned long long request_id;
    unsigned int flags;
    unsigned int padding;
};

struct kp_cam_cmd_buf_desc {
    int mem_handle;
    unsigned int offset;
    unsigned int size;
    unsigned int length;
    unsigned int type;
    unsigned int meta_data;
};

struct kp_cam_packet {
    struct kp_cam_packet_header header;

    unsigned int cmd_buf_offset;
    unsigned int num_cmd_buf;

    unsigned int io_configs_offset;
    unsigned int num_io_configs;

    unsigned int patch_offset;
    unsigned int num_patches;

    unsigned int kmd_cmd_buf_index;
    unsigned int kmd_cmd_buf_offset;

    unsigned long long payload[1];
};

/*
 * Minimal layout of cam_mem_cache_ops_cmd.
 *
 * cam_mem_mgr.c accesses:
 *   cmd->buf_handle
 *   cmd->mem_cache_ops
 *
 * Keep these fields first.
 */
struct kp_cam_mem_cache_ops_cmd {
    int buf_handle;
    unsigned int mem_cache_ops;
};

/*
 * Values used by cam_mem_mgr.c.
 *
 * If your local cam_req_mgr.h exposes these symbols directly,
 * they can be used instead.
 */
#define KP_CAM_MEM_CLEAN_CACHE      0
#define KP_CAM_MEM_INV_CACHE        1
#define KP_CAM_MEM_CLEAN_INV_CACHE  2


static unsigned long addr_prepare;

static int (*p_cam_mem_get_cpu_buf)(
        int buf_handle,
        unsigned long *vaddr_ptr,
        unsigned long *len);

static int (*p_cam_mem_mgr_cache_ops)(
        struct kp_cam_mem_cache_ops_cmd *cmd);


static DEFINE_MUTEX(inject_lock);

static unsigned char *inject_data;
static unsigned long inject_size;

static unsigned long frame_index;

static int inject_mode = INJECT_DISABLED;

static unsigned int last_width;
static unsigned int last_height;
static unsigned int last_stride[MAX_PLANES];
static unsigned int last_slice_height[MAX_PLANES];
static unsigned int last_plane_bytes[MAX_PLANES];
static unsigned int last_plane_count;

static int inject_count;


static int file_read_all(
        const char *path,
        unsigned char **out_buf,
        unsigned long *out_size)
{
    struct file *file;
    loff_t pos = 0;
    ssize_t n;
    unsigned char *buf;
    unsigned long size;
    unsigned long done = 0;

    if (!path || !out_buf || !out_size)
        return -EINVAL;

    file = filp_open(path, O_RDONLY, 0);

    if (IS_ERR(file)) {
        pr_info(
            "cam-ubwc-injector: filp_open failed path=%s rc=%ld\n",
            path,
            PTR_ERR(file));
        return PTR_ERR(file);
    }

    size = i_size_read(file_inode(file));

    if (!size || size > MAX_FILE_SIZE) {
        pr_info(
            "cam-ubwc-injector: invalid file size=%lu\n",
            size);

        filp_close(file, NULL);
        return -EINVAL;
    }

    buf = vmalloc(size);

    if (!buf) {
        filp_close(file, NULL);
        return -ENOMEM;
    }

    while (done < size) {
        unsigned long remain = size - done;
        unsigned long chunk = min(remain, 1024UL * 1024UL);

        n = kernel_read(
            file,
            buf + done,
            chunk,
            &pos);

        if (n <= 0) {
            pr_info(
                "cam-ubwc-injector: kernel_read failed "
                "done=%lu size=%lu rc=%zd\n",
                done,
                size,
                n);

            vfree(buf);
            filp_close(file, NULL);
            return -EIO;
        }

        done += n;
    }

    filp_close(file, NULL);

    *out_buf = buf;
    *out_size = size;

    return 0;
}


static int clean_buffer_cache(int handle)
{
    struct kp_cam_mem_cache_ops_cmd cmd;

    if (!p_cam_mem_mgr_cache_ops)
        return 0;

    memset(&cmd, 0, sizeof(cmd));

    cmd.buf_handle = handle;
    cmd.mem_cache_ops = KP_CAM_MEM_CLEAN_CACHE;

    return p_cam_mem_mgr_cache_ops(&cmd);
}


static unsigned long calc_frame_size(
        struct kp_cam_buf_io_cfg *cfg,
        unsigned int *plane_count)
{
    unsigned int i;
    unsigned long total = 0;

    if (!cfg || !plane_count)
        return 0;

    *plane_count = 0;

    for (i = 0; i < MAX_PLANES; i++) {

        unsigned long bytes;

        if (!cfg->mem_handle[i])
            break;

        if (!cfg->planes[i].plane_stride ||
            !cfg->planes[i].slice_height)
            return 0;

        bytes =
            (unsigned long)cfg->planes[i].plane_stride *
            (unsigned long)cfg->planes[i].slice_height;

        total += bytes;

        *plane_count = i + 1;
    }

    return total;
}


static int inject_one_cfg(
        struct kp_cam_buf_io_cfg *cfg,
        unsigned long long request_id)
{
    unsigned int i;
    unsigned int plane_count;
    unsigned long frame_size;
    unsigned long frame_off;

    unsigned int width;
    unsigned int height;

    int injected = 0;

    if (!cfg)
        return 0;

    if (cfg->direction != CAM_BUF_INPUT)
        return 0;

    if (cfg->format != CAM_FORMAT_TP10)
        return 0;

    width = cfg->planes[0].width;
    height = cfg->planes[0].height;

    /*
     * We deliberately only inject TP10 here.
     * The actual dimensions are taken from the current request.
     */
    frame_size = calc_frame_size(
        cfg,
        &plane_count);

    if (!frame_size || !plane_count)
        return 0;

    mutex_lock(&inject_lock);

    if (!inject_data || !inject_size) {
        mutex_unlock(&inject_lock);
        return 0;
    }

    /*
     * The uploaded file contains:
     *
     *   frame0 plane0
     *   frame0 plane1
     *   frame1 plane0
     *   frame1 plane1
     *   ...
     *
     * No header.
     */
    if (inject_size < frame_size) {
        pr_info(
            "cam-ubwc-injector: file too small "
            "req=%llu file=%lu frame=%lu\n",
            request_id,
            inject_size,
            frame_size);

        mutex_unlock(&inject_lock);
        return 0;
    }

    if (inject_size % frame_size != 0) {
        pr_info(
            "cam-ubwc-injector: file size mismatch "
            "req=%llu file=%lu frame=%lu remainder=%lu\n",
            request_id,
            inject_size,
            frame_size,
            inject_size % frame_size);

        mutex_unlock(&inject_lock);
        return 0;
    }

    frame_off =
        (frame_index % (inject_size / frame_size)) *
        frame_size;

    for (i = 0; i < plane_count; i++) {

        unsigned long cpu_addr = 0;
        unsigned long buf_len = 0;
        unsigned long plane_bytes;
        unsigned long dst_off;

        int rc;

        plane_bytes =
            (unsigned long)cfg->planes[i].plane_stride *
            (unsigned long)cfg->planes[i].slice_height;

        dst_off = cfg->offsets[i];

        rc = p_cam_mem_get_cpu_buf(
            cfg->mem_handle[i],
            &cpu_addr,
            &buf_len);

        if (rc || !cpu_addr || !buf_len) {
            pr_info(
                "cam-ubwc-injector: "
                "get_cpu_buf failed "
                "req=%llu plane=%u handle=%d rc=%d len=%lu\n",
                request_id,
                i,
                cfg->mem_handle[i],
                rc,
                buf_len);

            mutex_unlock(&inject_lock);
            return 0;
        }

        if (dst_off >= buf_len ||
            plane_bytes > buf_len - dst_off) {

            pr_info(
                "cam-ubwc-injector: "
                "buffer too small "
                "req=%llu plane=%u "
                "off=%lu plane=%lu buf=%lu\n",
                request_id,
                i,
                dst_off,
                plane_bytes,
                buf_len);

            mutex_unlock(&inject_lock);
            return 0;
        }

        memcpy(
            (void *)(cpu_addr + dst_off),
            inject_data + frame_off,
            plane_bytes);

        rc = clean_buffer_cache(
            cfg->mem_handle[i]);

        if (rc) {
            pr_info(
                "cam-ubwc-injector: "
                "cache clean failed "
                "req=%llu plane=%u rc=%d\n",
                request_id,
                i,
                rc);

            mutex_unlock(&inject_lock);
            return 0;
        }

        frame_off += plane_bytes;

        last_stride[i] =
            cfg->planes[i].plane_stride;

        last_slice_height[i] =
            cfg->planes[i].slice_height;

        last_plane_bytes[i] =
            plane_bytes;

        injected = 1;
    }

    last_width = width;
    last_height = height;
    last_plane_count = plane_count;

    frame_index++;
    inject_count++;

    if (inject_mode == INJECT_ONCE)
        inject_mode = INJECT_DISABLED;

    mutex_unlock(&inject_lock);

    return injected;
}


static int inject_packet_inputs(
        struct kp_cam_packet *packet)
{
    struct kp_cam_buf_io_cfg *io_cfg;

    unsigned int i;
    int injected = 0;

    if (!packet)
        return 0;

    if (!packet->num_io_configs ||
        packet->num_io_configs > MAX_IO_CFG)
        return 0;

    io_cfg =
        (struct kp_cam_buf_io_cfg *)(
            (unsigned char *)packet->payload +
            packet->io_configs_offset);

    for (i = 0;
         i < packet->num_io_configs;
         i++) {

        if (inject_mode == INJECT_DISABLED)
            break;

        if (io_cfg[i].direction != CAM_BUF_INPUT)
            continue;

        if (io_cfg[i].format != CAM_FORMAT_TP10)
            continue;

        if (inject_one_cfg(
                &io_cfg[i],
                packet->header.request_id))
            injected++;
    }

    return injected;
}


static void before_prepare(
        hook_fargs2_t *args,
        void *udata)
{
    struct kp_cam_packet *packet;
    int injected;

    /*
     * Keep this path extremely cheap when disabled.
     */
    if (inject_mode == INJECT_DISABLED)
        return;

    packet =
        *(struct kp_cam_packet **)args->arg1;

    if (!packet)
        return;

    injected =
        inject_packet_inputs(packet);

    if (injected) {
        pr_info(
            "cam-ubwc-injector: "
            "REQ=%llu injected=%d frame=%lu "
            "size=%lu %ux%u planes=%u\n",
            packet->header.request_id,
            injected,
            frame_index - 1,
            inject_size,
            last_width,
            last_height,
            last_plane_count);
    }
}


static int load_frame_file(
        const char *path)
{
    unsigned char *new_data = NULL;
    unsigned long new_size = 0;
    unsigned char *old_data;
    int rc;

    rc = file_read_all(
        path,
        &new_data,
        &new_size);

    if (rc)
        return rc;

    mutex_lock(&inject_lock);

    old_data = inject_data;

    inject_data = new_data;
    inject_size = new_size;

    frame_index = 0;
    inject_count = 0;

    last_width = 0;
    last_height = 0;
    last_plane_count = 0;

    memset(
        last_stride,
        0,
        sizeof(last_stride));

    memset(
        last_slice_height,
        0,
        sizeof(last_slice_height));

    memset(
        last_plane_bytes,
        0,
        sizeof(last_plane_bytes));

    mutex_unlock(&inject_lock);

    if (old_data)
        vfree(old_data);

    pr_info(
        "cam-ubwc-injector: loaded "
        "%s size=%lu\n",
        path,
        new_size);

    return 0;
}


static void report_status(
        char *out,
        unsigned int outlen)
{
    unsigned long total_frames = 0;

    if (!out || !outlen)
        return;

    mutex_lock(&inject_lock);

    if (inject_size && last_width) {

        unsigned long frame_size = 0;
        unsigned int i;

        for (i = 0; i < last_plane_count; i++)
            frame_size += last_plane_bytes[i];

        if (frame_size)
            total_frames =
                inject_size / frame_size;
    }

    scnprintf(
        out,
        outlen,
        "mode=%d size=%lu frame=%lu injected=%d "
        "last=%ux%u planes=%u frames=%lu",
        inject_mode,
        inject_size,
        frame_index,
        inject_count,
        last_width,
        last_height,
        last_plane_count,
        total_frames);

    mutex_unlock(&inject_lock);
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

    p_cam_mem_mgr_cache_ops =
        (void *)kallsyms_lookup_name(
            "cam_mem_mgr_cache_ops");

    pr_info(
        "cam-ubwc-injector: "
        "prepare=%lx get_cpu=%lx cache=%lx\n",
        addr_prepare,
        (unsigned long)p_cam_mem_get_cpu_buf,
        (unsigned long)p_cam_mem_mgr_cache_ops);

    if (!addr_prepare ||
        !p_cam_mem_get_cpu_buf)
        return -1;

    if (hook_wrap2(
            (void *)addr_prepare,
            before_prepare,
            NULL,
            NULL))
        return -1;

    pr_info(
        "cam-ubwc-injector: init ok\n");

    return 0;
}


static long cam_kpm_control0(
        const char *args,
        char __user *out_msg,
        int outlen)
{
    char reply[192];

    if (!args)
        return -EINVAL;

    memset(reply, 0, sizeof(reply));

    /*
     * load:/data/local/tmp/test.tp10v
     */
    if (!strncmp(args, "load:", 5)) {

        int rc;

        rc = load_frame_file(
            args + 5);

        if (rc) {
            scnprintf(
                reply,
                sizeof(reply),
                "load failed rc=%d",
                rc);
        } else {
            scnprintf(
                reply,
                sizeof(reply),
                "load ok size=%lu",
                inject_size);
        }

        compat_copy_to_user(
            out_msg,
            reply,
            min((unsigned int)strlen(reply) + 1,
                (unsigned int)outlen));

        return 0;
    }

    if (!strcmp(args, "start") ||
        !strcmp(args, "loop")) {

        mutex_lock(&inject_lock);

        if (!inject_data || !inject_size) {
            mutex_unlock(&inject_lock);

            compat_copy_to_user(
                out_msg,
                "no frame loaded",
                16);

            return 0;
        }

        frame_index = 0;
        inject_count = 0;
        inject_mode = INJECT_LOOP;

        mutex_unlock(&inject_lock);

        compat_copy_to_user(
            out_msg,
            "started",
            8);

        pr_info(
            "cam-ubwc-injector: continuous mode\n");

        return 0;
    }

    if (!strcmp(args, "once")) {

        mutex_lock(&inject_lock);

        if (!inject_data || !inject_size) {
            mutex_unlock(&inject_lock);

            compat_copy_to_user(
                out_msg,
                "no frame loaded",
                16);

            return 0;
        }

        inject_mode = INJECT_ONCE;

        mutex_unlock(&inject_lock);

        compat_copy_to_user(
            out_msg,
            "armed once",
            10);

        pr_info(
            "cam-ubwc-injector: one-shot mode\n");

        return 0;
    }

    if (!strcmp(args, "stop")) {

        mutex_lock(&inject_lock);
        inject_mode = INJECT_DISABLED;
        mutex_unlock(&inject_lock);

        compat_copy_to_user(
            out_msg,
            "stopped",
            8);

        pr_info(
            "cam-ubwc-injector: stopped\n");

        return 0;
    }

    if (!strcmp(args, "status")) {

        report_status(
            reply,
            sizeof(reply));

        compat_copy_to_user(
            out_msg,
            reply,
            min((unsigned int)strlen(reply) + 1,
                (unsigned int)outlen));

        return 0;
    }

    if (!strcmp(args, "reset")) {

        mutex_lock(&inject_lock);

        frame_index = 0;
        inject_count = 0;

        mutex_unlock(&inject_lock);

        compat_copy_to_user(
            out_msg,
            "reset",
            6);

        return 0;
    }

    compat_copy_to_user(
        out_msg,
        "commands: load:<path> start once stop status reset",
        49);

    return 0;
}


static long cam_kpm_exit(
        void *reserved)
{
    unsigned char *old_data;

    inject_mode = INJECT_DISABLED;

    if (addr_prepare)
        unhook((void *)addr_prepare);

    mutex_lock(&inject_lock);
    old_data = inject_data;
    inject_data = NULL;
    inject_size = 0;
    mutex_unlock(&inject_lock);

    if (old_data)
        vfree(old_data);

    pr_info(
        "cam-ubwc-injector: exit\n");

    return 0;
}


KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
