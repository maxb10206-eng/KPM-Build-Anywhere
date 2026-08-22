#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-ubwc-frame-injector");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Inject deterministic TP10 test frames into CAM_BUF_INPUT");

/*
 * From the camera-kernel UAPI we inspected.
 */
#define CAM_BUF_INPUT       1
#define CAM_FORMAT_TP10     33

#define MAX_IO_CFG           32
#define MAX_PLANE             2

#define INJECT_OFF            0
#define INJECT_ONCE           1
#define INJECT_LOOP           2

#define PATTERN_FLAT_BLACK    0
#define PATTERN_FLAT_WHITE    1
#define PATTERN_HORIZONTAL    2
#define PATTERN_VERTICAL      3
#define PATTERN_MOVING_BAR    4


/*
 * cam_plane_cfg
 *
 * camera-kernel/include/uapi/camera/media/cam_defs.h
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


/*
 * cam_buf_io_cfg
 */
struct kp_cam_buf_io_cfg {
    int mem_handle[MAX_PLANE];
    unsigned int offsets[MAX_PLANE];

    struct kp_cam_plane_cfg planes[MAX_PLANE];

    unsigned int format;
    unsigned int color_space;
    unsigned int color_pattern;
    unsigned int bpp;
    unsigned int rotation;
    unsigned int resource_type;

    int fence;
    int early_fence;

    /*
     * We do not access aux_cmd_buf.
     * Reserve enough space so following fields remain
     * at approximately the same ABI position.
     */
    unsigned int aux_cmd_buf[8];

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
 * cam_mem_cache_ops_cmd
 *
 * Only the fields used by cam_mem_mgr_cache_ops() matter here.
 *
 * The exact cache-op numeric values are not needed from the
 * headers for the compile-safe first version because we use
 * CLEAN_CACHE = 0 as defined by the camera memory manager
 * implementation we inspected.
 */
struct kp_cam_mem_cache_ops_cmd {
    int buf_handle;
    unsigned int mem_cache_ops;
};


/*
 * Function pointers resolved at runtime.
 */
static unsigned long addr_prepare;

static int (*p_cam_mem_get_cpu_buf)(
        int,
        unsigned long *,
        unsigned long *);

static int (*p_cam_mem_mgr_cache_ops)(
        struct kp_cam_mem_cache_ops_cmd *);


/*
 * Runtime state.
 *
 * No mutex / vmalloc / fs APIs are used.
 */
static volatile int inject_mode = INJECT_OFF;

static volatile unsigned int pattern_mode = PATTERN_MOVING_BAR;

static volatile unsigned long frame_counter;

static volatile unsigned long injection_counter;

static volatile unsigned int last_width;
static volatile unsigned int last_height;

static volatile unsigned int last_stride_y;
static volatile unsigned int last_stride_uv;

static volatile unsigned int last_slice_y;
static volatile unsigned int last_slice_uv;


/*
 * TP10 packing:
 *
 * 3 pixels -> 4 bytes
 *
 * Byte layout:
 *
 *  b0 = p0[9:2]
 *  b1 = p1[9:2]
 *  b2 = p2[9:2]
 *  b3 = p0[1:0] | p1[1:0]<<2 | p2[1:0]<<4
 *
 * This matches the byte-rate rule used by the driver's
 * BUS_RD_VER1 TP10 unpacker:
 *
 * ALIGNUP(pixels, 3) * 4 / 3
 */
static void tp10_pack_3(
        unsigned char *dst,
        unsigned int p0,
        unsigned int p1,
        unsigned int p2)
{
    dst[0] = (unsigned char)((p0 >> 2) & 0xFF);
    dst[1] = (unsigned char)((p1 >> 2) & 0xFF);
    dst[2] = (unsigned char)((p2 >> 2) & 0xFF);

    dst[3] =
        (unsigned char)(
            (p0 & 0x3) |
            ((p1 & 0x3) << 2) |
            ((p2 & 0x3) << 4));
}


/*
 * Generate one TP10 Y plane.
 *
 * The pattern is deterministic and changes with frame_counter.
 *
 * 0: black
 * 1: white
 * 2: horizontal gradient
 * 3: vertical gradient
 * 4: moving vertical bar
 */
static void generate_tp10_y(
        unsigned char *dst,
        unsigned int width,
        unsigned int height,
        unsigned int stride,
        unsigned int pattern,
        unsigned long frame)
{
    unsigned int y;
    unsigned int x;

    if (!dst || !width || !height || !stride)
        return;

    for (y = 0; y < height; y++) {

        unsigned char *row =
            dst + ((unsigned long)y * stride);

        for (x = 0; x < width; x += 3) {

            unsigned int x0 = x;
            unsigned int x1 = x + 1;
            unsigned int x2 = x + 2;

            unsigned int p0;
            unsigned int p1;
            unsigned int p2;

            if (x1 >= width)
                x1 = width - 1;

            if (x2 >= width)
                x2 = width - 1;

            switch (pattern) {

            case PATTERN_FLAT_BLACK:
                p0 = 64;
                p1 = 64;
                p2 = 64;
                break;

            case PATTERN_FLAT_WHITE:
                p0 = 940;
                p1 = 940;
                p2 = 940;
                break;

            case PATTERN_HORIZONTAL:
                p0 = 64 + (x0 * 876) / (width - 1);
                p1 = 64 + (x1 * 876) / (width - 1);
                p2 = 64 + (x2 * 876) / (width - 1);
                break;

            case PATTERN_VERTICAL:
                p0 = 64 + (y * 876) / (height - 1);
                p1 = p0;
                p2 = p0;
                break;

            case PATTERN_MOVING_BAR: {
                unsigned int period = width * 2;
                unsigned int center;

                if (!period)
                    period = 1;

                center =
                    (unsigned int)(
                        (frame * 32) %
                        period);

                if (center >= width)
                    center =
                        period - center - 1;

                if (x0 >= center &&
                    x0 < center + width / 8)
                    p0 = 940;
                else
                    p0 = 64;

                if (x1 >= center &&
                    x1 < center + width / 8)
                    p1 = 940;
                else
                    p1 = 64;

                if (x2 >= center &&
                    x2 < center + width / 8)
                    p2 = 940;
                else
                    p2 = 64;

                break;
            }

            default:
                p0 = 64;
                p1 = 64;
                p2 = 64;
                break;
            }

            tp10_pack_3(
                row + ((x / 3) * 4),
                p0,
                p1,
                p2);
        }
    }
}


/*
 * Generate TP10 UV plane.
 *
 * We keep U/V constant so that the experiment mainly changes
 * luma. This makes UBWC differential analysis much cleaner.
 *
 * For YUV420:
 *
 * UV height = Y height / 2
 *
 * UV is treated as interleaved 10-bit U/V data.
 */
static void generate_tp10_uv(
        unsigned char *dst,
        unsigned int width,
        unsigned int height,
        unsigned int stride)
{
    unsigned int y;
    unsigned int x;

    unsigned int uv_height = height / 2;

    if (!dst || !width || !uv_height || !stride)
        return;

    for (y = 0; y < uv_height; y++) {

        unsigned char *row =
            dst + ((unsigned long)y * stride);

        /*
         * Two 10-bit chroma samples are packed as:
         *
         * U, V, U, V, ...
         *
         * Each three 16-bit logical samples become a 4-byte
         * TP10 group in the same way as the Y plane.
         *
         * We keep chroma around neutral.
         */
        for (x = 0; x < width; x += 3) {

            unsigned int u0 = 512;
            unsigned int v0 = 512;
            unsigned int u1 = 512;
            unsigned int v1 = 512;
            unsigned int u2 = 512;
            unsigned int v2 = 512;

            unsigned int logical0;
            unsigned int logical1;
            unsigned int logical2;

            /*
             * For the initial injector we keep the chroma
             * samples neutral. The exact interleaving seen
             * by the hardware is still determined by the
             * plane's format configuration.
             */
            if ((x & 1) == 0) {
                logical0 = u0;
                logical1 = v0;
                logical2 = u1;
            } else {
                logical0 = v1;
                logical1 = u2;
                logical2 = v2;
            }

            tp10_pack_3(
                row + ((x / 3) * 4),
                logical0,
                logical1,
                logical2);
        }
    }
}


/*
 * Cache clean before VFE reads the buffer.
 */
static int clean_cache(
        int mem_handle)
{
    struct kp_cam_mem_cache_ops_cmd cmd;
    int rc;

    if (!p_cam_mem_mgr_cache_ops)
        return 0;

    cmd.buf_handle = mem_handle;
    cmd.mem_cache_ops = 0;

    rc =
        p_cam_mem_mgr_cache_ops(&cmd);

    return rc;
}


/*
 * Inject exactly one CAM_BUF_INPUT io configuration.
 */
static int inject_io_cfg(
        struct kp_cam_buf_io_cfg *cfg,
        unsigned long long request_id)
{
    unsigned long cpu_addr_y;
    unsigned long cpu_len_y;

    unsigned long cpu_addr_uv;
    unsigned long cpu_len_uv;

    unsigned int y_bytes;
    unsigned int uv_bytes;

    unsigned int width;
    unsigned int height;

    unsigned int stride_y;
    unsigned int stride_uv;

    unsigned int slice_y;
    unsigned int slice_uv;

    int rc;

    if (!cfg)
        return 0;

    if (cfg->direction != CAM_BUF_INPUT)
        return 0;

    if (cfg->format != CAM_FORMAT_TP10)
        return 0;

    if (!cfg->mem_handle[0])
        return 0;

    width =
        cfg->planes[0].width;

    height =
        cfg->planes[0].height;

    stride_y =
        cfg->planes[0].plane_stride;

    slice_y =
        cfg->planes[0].slice_height;

    if (!width ||
        !height ||
        !stride_y ||
        !slice_y)
        return 0;

    /*
     * Current experiment assumes 2-plane TP10:
     *
     *   plane 0 = Y
     *   plane 1 = UV
     */
    if (!cfg->mem_handle[1]) {
        pr_info(
            "cam-ubwc-injector: "
            "REQ=%llu TP10 input has no UV plane\n",
            request_id);
        return 0;
    }

    stride_uv =
        cfg->planes[1].plane_stride;

    slice_uv =
        cfg->planes[1].slice_height;

    if (!stride_uv || !slice_uv)
        return 0;

    y_bytes =
        stride_y * slice_y;

    uv_bytes =
        stride_uv * slice_uv;

    cpu_addr_y = 0;
    cpu_len_y = 0;

    cpu_addr_uv = 0;
    cpu_len_uv = 0;

    rc =
        p_cam_mem_get_cpu_buf(
            cfg->mem_handle[0],
            &cpu_addr_y,
            &cpu_len_y);

    if (rc ||
        !cpu_addr_y ||
        !cpu_len_y) {

        pr_info(
            "cam-ubwc-injector: "
            "REQ=%llu get Y CPU buf failed "
            "handle=%d rc=%d len=%lu\n",
            request_id,
            cfg->mem_handle[0],
            rc,
            cpu_len_y);

        return 0;
    }

    rc =
        p_cam_mem_get_cpu_buf(
            cfg->mem_handle[1],
            &cpu_addr_uv,
            &cpu_len_uv);

    if (rc ||
        !cpu_addr_uv ||
        !cpu_len_uv) {

        pr_info(
            "cam-ubwc-injector: "
            "REQ=%llu get UV CPU buf failed "
            "handle=%d rc=%d len=%lu\n",
            request_id,
            cfg->mem_handle[1],
            rc,
            cpu_len_uv);

        return 0;
    }

    if (y_bytes > cpu_len_y) {

        pr_info(
            "cam-ubwc-injector: "
            "REQ=%llu Y buffer too small "
            "need=%u have=%lu\n",
            request_id,
            y_bytes,
            cpu_len_y);

        return 0;
    }

    if (uv_bytes > cpu_len_uv) {

        pr_info(
            "cam-ubwc-injector: "
            "REQ=%llu UV buffer too small "
            "need=%u have=%lu\n",
            request_id,
            uv_bytes,
            cpu_len_uv);

        return 0;
    }

    /*
     * Generate directly in the actual Camera input buffers.
     *
     * No extra large kernel buffer is required.
     */
    generate_tp10_y(
        (unsigned char *)cpu_addr_y,
        width,
        height,
        stride_y,
        pattern_mode,
        frame_counter);

    generate_tp10_uv(
        (unsigned char *)cpu_addr_uv,
        width,
        height,
        stride_uv);

    /*
     * Give the DMA device the CPU-written data.
     */
    rc =
        clean_cache(
            cfg->mem_handle[0]);

    if (rc) {

        pr_info(
            "cam-ubwc-injector: "
            "REQ=%llu Y cache clean failed rc=%d\n",
            request_id,
            rc);

        return 0;
    }

    rc =
        clean_cache(
            cfg->mem_handle[1]);

    if (rc) {

        pr_info(
            "cam-ubwc-injector: "
            "REQ=%llu UV cache clean failed rc=%d\n",
            request_id,
            rc);

        return 0;
    }

    last_width = width;
    last_height = height;

    last_stride_y = stride_y;
    last_stride_uv = stride_uv;

    last_slice_y = slice_y;
    last_slice_uv = slice_uv;

    injection_counter++;

    frame_counter++;

    if (inject_mode == INJECT_ONCE)
        inject_mode = INJECT_OFF;

    pr_info(
        "cam-ubwc-injector: "
        "REQ=%llu injected frame=%lu "
        "%ux%u "
        "Y[stride=%u slice=%u bytes=%u] "
        "UV[stride=%u slice=%u bytes=%u] "
        "pattern=%u\n",
        request_id,
        frame_counter - 1,
        width,
        height,
        stride_y,
        slice_y,
        y_bytes,
        stride_uv,
        slice_uv,
        uv_bytes,
        pattern_mode);

    return 1;
}


/*
 * Scan the packet's IO configurations and replace
 * the TP10 input buffer contents.
 */
static int inject_packet(
        struct kp_cam_packet *packet)
{
    struct kp_cam_buf_io_cfg *io_cfg;
    unsigned int i;
    int count = 0;

    if (!packet)
        return 0;

    if (!packet->num_io_configs ||
        packet->num_io_configs > MAX_IO_CFG)
        return 0;

    if (inject_mode == INJECT_OFF)
        return 0;

    io_cfg =
        (struct kp_cam_buf_io_cfg *)(
            (unsigned char *)packet->payload +
            packet->io_configs_offset);

    for (i = 0;
         i < packet->num_io_configs;
         i++) {

        if (io_cfg[i].direction != CAM_BUF_INPUT)
            continue;

        if (io_cfg[i].format != CAM_FORMAT_TP10)
            continue;

        count +=
            inject_io_cfg(
                &io_cfg[i],
                packet->header.request_id);

        /*
         * We only want the first TP10 input of a request.
         */
        if (count)
            break;
    }

    return count;
}


static void before_prepare(
        hook_fargs2_t *args,
        void *udata)
{
    struct kp_cam_packet *packet;
    int count;

    if (inject_mode == INJECT_OFF)
        return;

    packet =
        *(struct kp_cam_packet **)args->arg1;

    if (!packet)
        return;

    count =
        inject_packet(packet);

    if (count) {

        pr_info(
            "cam-ubwc-injector: "
            "PREP req=%llu "
            "injected=%d "
            "total=%lu\n",
            packet->header.request_id,
            count,
            injection_counter);
    }
}


/*
 * KPM init
 */
static long cam_kpm_init(
        const char *args,
        const char *event,
        void *reserved)
{
    int rc;

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
        "prepare=%lx "
        "get_cpu=%lx "
        "cache=%lx\n",
        addr_prepare,
        (unsigned long)p_cam_mem_get_cpu_buf,
        (unsigned long)p_cam_mem_mgr_cache_ops);

    if (!addr_prepare) {
        pr_info(
            "cam-ubwc-injector: "
            "prepare symbol not found\n");
        return -1;
    }

    if (!p_cam_mem_get_cpu_buf) {
        pr_info(
            "cam-ubwc-injector: "
            "cam_mem_get_cpu_buf not found\n");
        return -1;
    }

    /*
     * Cache API is optional in the first version.
     * The injector can still run on uncached buffers.
     */
    if (p_cam_mem_mgr_cache_ops == 0) {
        pr_info(
            "cam-ubwc-injector: "
            "cache_ops symbol not found\n");
    }

    rc =
        hook_wrap2(
            (void *)addr_prepare,
            before_prepare,
            NULL,
            NULL);

    if (rc) {
        pr_info(
            "cam-ubwc-injector: "
            "hook failed rc=%d\n",
            rc);
        return -1;
    }

    inject_mode = INJECT_OFF;
    pattern_mode = PATTERN_MOVING_BAR;
    frame_counter = 0;
    injection_counter = 0;

    pr_info(
        "cam-ubwc-injector: init ok\n");

    return 0;
}


/*
 * KPM control interface.
 *
 * Commands:
 *
 *   start
 *   once
 *   stop
 *
 *   black
 *   white
 *   hgrad
 *   vgrad
 *   bar
 *
 *   status
 *   reset
 */
static long cam_kpm_control0(
        const char *args,
        char __user *out_msg,
        int outlen)
{
    const char *reply = "ok";

    if (!args)
        return -1;

    if (!strcmp(args, "start")) {

        inject_mode = INJECT_LOOP;

        reply = "started";

        pr_info(
            "cam-ubwc-injector: "
            "continuous injection enabled\n");

    } else if (!strcmp(args, "once")) {

        inject_mode = INJECT_ONCE;

        reply = "armed once";

        pr_info(
            "cam-ubwc-injector: "
            "one-shot injection enabled\n");

    } else if (!strcmp(args, "stop")) {

        inject_mode = INJECT_OFF;

        reply = "stopped";

        pr_info(
            "cam-ubwc-injector: "
            "injection stopped\n");

    } else if (!strcmp(args, "black")) {

        pattern_mode = PATTERN_FLAT_BLACK;

        reply = "black";

    } else if (!strcmp(args, "white")) {

        pattern_mode = PATTERN_FLAT_WHITE;

        reply = "white";

    } else if (!strcmp(args, "hgrad")) {

        pattern_mode = PATTERN_HORIZONTAL;

        reply = "horizontal";

    } else if (!strcmp(args, "vgrad")) {

        pattern_mode = PATTERN_VERTICAL;

        reply = "vertical";

    } else if (!strcmp(args, "bar")) {

        pattern_mode = PATTERN_MOVING_BAR;

        reply = "moving-bar";

    } else if (!strcmp(args, "reset")) {

        frame_counter = 0;
        injection_counter = 0;

        reply = "reset";

    } else if (!strcmp(args, "status")) {

        static char msg[256];

        /*
         * Avoid relying on snprintf from the full kernel headers.
         * kstrto* / printk facilities are intentionally kept out.
         */
        pr_info(
            "cam-ubwc-injector: "
            "status mode=%d pattern=%d "
            "frames=%lu injected=%lu "
            "last=%ux%u "
            "Y[%u,%u] UV[%u,%u]\n",
            inject_mode,
            pattern_mode,
            frame_counter,
            injection_counter,
            last_width,
            last_height,
            last_stride_y,
            last_slice_y,
            last_stride_uv,
            last_slice_uv);

        reply = "status printed";

    } else {

        reply =
            "start once stop black white hgrad vgrad bar status reset";
    }

    compat_copy_to_user(
        out_msg,
        reply,
        (unsigned int)strlen(reply) + 1);

    return 0;
}


static long cam_kpm_exit(
        void *reserved)
{
    inject_mode = INJECT_OFF;

    if (addr_prepare)
        unhook(
            (void *)addr_prepare);

    pr_info(
        "cam-ubwc-injector: exit\n");

    return 0;
}


KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
