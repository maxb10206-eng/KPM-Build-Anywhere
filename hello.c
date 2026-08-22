#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-ubwc-frame-injector");
KPM_VERSION("1.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Inject deterministic TP10 test frames into CAM_BUF_INPUT");

#define CAM_BUF_INPUT       1
#define CAM_FORMAT_TP10     33

#define MAX_IO_CFG          32
#define MAX_PLANE            2

#define INJECT_OFF           0
#define INJECT_ONCE          1
#define INJECT_LOOP          2

#define PATTERN_BLACK        0
#define PATTERN_WHITE        1
#define PATTERN_HGRAD        2
#define PATTERN_VGRAD        3
#define PATTERN_BAR          4

#define CACHE_CLEAN          0

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

struct kp_cam_mem_cache_ops_cmd {
    int buf_handle;
    unsigned int mem_cache_ops;
};

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
 * Keep this very small so that the module has very little
 * .bss/.data relocation pressure.
 */
static volatile int inject_mode;
static volatile unsigned int pattern_mode;

static volatile unsigned long frame_counter;
static volatile unsigned long inject_counter;

static volatile unsigned int last_width;
static volatile unsigned int last_height;

static volatile unsigned int last_stride_y;
static volatile unsigned int last_stride_uv;

static volatile unsigned int last_slice_y;
static volatile unsigned int last_slice_uv;


/*
 * Local strlen replacement.
 */
static unsigned int kp_strlen(
    const char *s)
{
    unsigned int n = 0;

    if (!s)
        return 0;

    while (s[n])
        n++;

    return n;
}


/*
 * Local exact string comparison.
 */
static int kp_streq(
    const char *a,
    const char *b)
{
    unsigned int i = 0;

    if (!a || !b)
        return 0;

    while (a[i] && b[i]) {
        if (a[i] != b[i])
            return 0;
        i++;
    }

    if (a[i] != b[i])
        return 0;

    return 1;
}


/*
 * Local byte copy.
 *
 * This deliberately avoids a possible compiler-generated
 * external memcpy reference.
 */
static void kp_copy_bytes(
    unsigned char *dst,
    const unsigned char *src,
    unsigned long size)
{
    unsigned long i;

    if (!dst || !src)
        return;

    for (i = 0; i < size; i++)
        dst[i] = src[i];
}


/*
 * TP10:
 *
 * 3 logical 10-bit samples -> 4 bytes.
 */
static void tp10_pack3(
    unsigned char *dst,
    unsigned int p0,
    unsigned int p1,
    unsigned int p2)
{
    if (!dst)
        return;

    dst[0] = (unsigned char)((p0 >> 2) & 0xff);
    dst[1] = (unsigned char)((p1 >> 2) & 0xff);
    dst[2] = (unsigned char)((p2 >> 2) & 0xff);

    dst[3] = (unsigned char)(
        (p0 & 0x3) |
        ((p1 & 0x3) << 2) |
        ((p2 & 0x3) << 4));
}


/*
 * Generate Y.
 */
static void generate_y(
    unsigned char *dst,
    unsigned int width,
    unsigned int height,
    unsigned int stride,
    unsigned int pattern,
    unsigned long frame)
{
    unsigned int y;
    unsigned int x;

    if (!dst)
        return;

    if (!width || !height || !stride)
        return;

    for (y = 0; y < height; y++) {

        unsigned char *row;
        unsigned int groups;

        row =
            dst + ((unsigned long)y * stride);

        groups =
            (width + 2) / 3;

        for (x = 0; x < groups; x++) {

            unsigned int px0;
            unsigned int px1;
            unsigned int px2;

            unsigned int p0;
            unsigned int p1;
            unsigned int p2;

            px0 = x * 3;
            px1 = px0 + 1;
            px2 = px0 + 2;

            if (px1 >= width)
                px1 = width - 1;

            if (px2 >= width)
                px2 = width - 1;

            p0 = 64;
            p1 = 64;
            p2 = 64;

            if (pattern == PATTERN_BLACK) {

                p0 = 64;
                p1 = 64;
                p2 = 64;

            } else if (pattern == PATTERN_WHITE) {

                p0 = 940;
                p1 = 940;
                p2 = 940;

            } else if (pattern == PATTERN_HGRAD) {

                if (width > 1) {
                    p0 = 64 + (px0 * 876) / (width - 1);
                    p1 = 64 + (px1 * 876) / (width - 1);
                    p2 = 64 + (px2 * 876) / (width - 1);
                }

            } else if (pattern == PATTERN_VGRAD) {

                if (height > 1) {
                    unsigned int v;

                    v = 64 + (y * 876) / (height - 1);

                    p0 = v;
                    p1 = v;
                    p2 = v;
                }

            } else if (pattern == PATTERN_BAR) {

                unsigned int period;
                unsigned int center;
                unsigned int bar_width;

                period = width * 2;

                if (!period)
                    period = 1;

                center =
                    (unsigned int)(
                        (frame * 32) % period);

                if (center >= width)
                    center =
                        period - center - 1;

                bar_width =
                    width / 8;

                if (!bar_width)
                    bar_width = 1;

                if (px0 >= center &&
                    px0 < center + bar_width)
                    p0 = 940;
                else
                    p0 = 64;

                if (px1 >= center &&
                    px1 < center + bar_width)
                    p1 = 940;
                else
                    p1 = 64;

                if (px2 >= center &&
                    px2 < center + bar_width)
                    p2 = 940;
                else
                    p2 = 64;
            }

            tp10_pack3(
                row + (x * 4),
                p0,
                p1,
                p2);
        }
    }
}


/*
 * Generate neutral chroma.
 *
 * Keep this intentionally simple.
 */
static void generate_uv(
    unsigned char *dst,
    unsigned int width,
    unsigned int height,
    unsigned int stride)
{
    unsigned int y;
    unsigned int x;
    unsigned int uv_height;

    if (!dst)
        return;

    if (!width || !height || !stride)
        return;

    uv_height = height / 2;

    for (y = 0; y < uv_height; y++) {

        unsigned char *row;
        unsigned int groups;

        row =
            dst + ((unsigned long)y * stride);

        groups =
            (width + 2) / 3;

        for (x = 0; x < groups; x++) {

            /*
             * Neutral chroma.
             */
            tp10_pack3(
                row + (x * 4),
                512,
                512,
                512);
        }
    }
}


/*
 * Cache maintenance.
 */
static int clean_cache(
    int handle)
{
    struct kp_cam_mem_cache_ops_cmd cmd;

    if (!p_cam_mem_mgr_cache_ops)
        return 0;

    cmd.buf_handle = handle;
    cmd.mem_cache_ops = CACHE_CLEAN;

    return p_cam_mem_mgr_cache_ops(&cmd);
}


/*
 * Inject one TP10 request.
 */
static int inject_cfg(
    struct kp_cam_buf_io_cfg *cfg,
    unsigned long long request_id)
{
    unsigned long y_addr = 0;
    unsigned long y_len = 0;

    unsigned long uv_addr = 0;
    unsigned long uv_len = 0;

    unsigned int width;
    unsigned int height;

    unsigned int stride_y;
    unsigned int stride_uv;

    unsigned int slice_y;
    unsigned int slice_uv;

    unsigned long y_bytes;
    unsigned long uv_bytes;

    int rc;

    if (!cfg)
        return 0;

    if (cfg->direction != CAM_BUF_INPUT)
        return 0;

    if (cfg->format != CAM_FORMAT_TP10)
        return 0;

    if (!cfg->mem_handle[0] ||
        !cfg->mem_handle[1])
        return 0;

    width =
        cfg->planes[0].width;

    height =
        cfg->planes[0].height;

    stride_y =
        cfg->planes[0].plane_stride;

    slice_y =
        cfg->planes[0].slice_height;

    stride_uv =
        cfg->planes[1].plane_stride;

    slice_uv =
        cfg->planes[1].slice_height;

    if (!width ||
        !height ||
        !stride_y ||
        !stride_uv ||
        !slice_y ||
        !slice_uv)
        return 0;

    y_bytes =
        (unsigned long)stride_y *
        (unsigned long)slice_y;

    uv_bytes =
        (unsigned long)stride_uv *
        (unsigned long)slice_uv;

    rc =
        p_cam_mem_get_cpu_buf(
            cfg->mem_handle[0],
            &y_addr,
            &y_len);

    if (rc ||
        !y_addr ||
        y_bytes > y_len) {

        pr_info(
            "cam-ubwc: Y buffer fail "
            "req=%llu handle=%d rc=%d "
            "need=%lu have=%lu\n",
            request_id,
            cfg->mem_handle[0],
            rc,
            y_bytes,
            y_len);

        return 0;
    }

    rc =
        p_cam_mem_get_cpu_buf(
            cfg->mem_handle[1],
            &uv_addr,
            &uv_len);

    if (rc ||
        !uv_addr ||
        uv_bytes > uv_len) {

        pr_info(
            "cam-ubwc: UV buffer fail "
            "req=%llu handle=%d rc=%d "
            "need=%lu have=%lu\n",
            request_id,
            cfg->mem_handle[1],
            rc,
            uv_bytes,
            uv_len);

        return 0;
    }

    /*
     * Respect user-space specified offsets.
     */
    if ((unsigned long)cfg->offsets[0] >= y_len ||
        y_bytes >
        y_len - (unsigned long)cfg->offsets[0]) {

        pr_info(
            "cam-ubwc: invalid Y offset "
            "req=%llu off=%u len=%lu buf=%lu\n",
            request_id,
            cfg->offsets[0],
            y_bytes,
            y_len);

        return 0;
    }

    if ((unsigned long)cfg->offsets[1] >= uv_len ||
        uv_bytes >
        uv_len - (unsigned long)cfg->offsets[1]) {

        pr_info(
            "cam-ubwc: invalid UV offset "
            "req=%llu off=%u len=%lu buf=%lu\n",
            request_id,
            cfg->offsets[1],
            uv_bytes,
            uv_len);

        return 0;
    }

    y_addr += cfg->offsets[0];
    uv_addr += cfg->offsets[1];

    generate_y(
        (unsigned char *)y_addr,
        width,
        height,
        stride_y,
        pattern_mode,
        frame_counter);

    generate_uv(
        (unsigned char *)uv_addr,
        width,
        height,
        stride_uv);

    rc =
        clean_cache(
            cfg->mem_handle[0]);

    if (rc) {
        pr_info(
            "cam-ubwc: Y cache clean fail "
            "req=%llu rc=%d\n",
            request_id,
            rc);

        return 0;
    }

    rc =
        clean_cache(
            cfg->mem_handle[1]);

    if (rc) {
        pr_info(
            "cam-ubwc: UV cache clean fail "
            "req=%llu rc=%d\n",
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

    inject_counter++;
    frame_counter++;

    if (inject_mode == INJECT_ONCE)
        inject_mode = INJECT_OFF;

    pr_info(
        "cam-ubwc: INJECT "
        "req=%llu frame=%lu "
        "%ux%u "
        "Y stride=%u slice=%u "
        "UV stride=%u slice=%u "
        "pattern=%u total=%lu\n",
        request_id,
        frame_counter - 1,
        width,
        height,
        stride_y,
        slice_y,
        stride_uv,
        slice_uv,
        pattern_mode,
        inject_counter);

    return 1;
}


/*
 * Find the first TP10 CAM_BUF_INPUT.
 */
static int inject_packet(
    struct kp_cam_packet *packet)
{
    struct kp_cam_buf_io_cfg *io_cfg;

    unsigned int i;

    if (!packet)
        return 0;

    if (!packet->num_io_configs)
        return 0;

    if (packet->num_io_configs > MAX_IO_CFG)
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

        return inject_cfg(
            &io_cfg[i],
            packet->header.request_id);
    }

    return 0;
}


/*
 * Hook.
 *
 * Use the exact hook_wrap2 style from the known-good KPM.
 */
static void before_prepare(
    hook_fargs2_t *args,
    void *udata)
{
    struct kp_cam_packet *packet;
    int rc;

    if (inject_mode == INJECT_OFF)
        return;

    packet =
        *(struct kp_cam_packet **)args->arg1;

    if (!packet)
        return;

    rc =
        inject_packet(packet);

    if (rc) {
        pr_info(
            "cam-ubwc: PREP injected "
            "req=%llu\n",
            packet->header.request_id);
    }
}


/*
 * KPM initialization.
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
        "cam-ubwc: prepare=%lx "
        "get_cpu_buf=%lx "
        "cache_ops=%lx\n",
        addr_prepare,
        (unsigned long)p_cam_mem_get_cpu_buf,
        (unsigned long)p_cam_mem_mgr_cache_ops);

    if (!addr_prepare)
        return -1;

    if (!p_cam_mem_get_cpu_buf)
        return -1;

    /*
     * Match the known-good KPM.
     */
    rc =
        hook_wrap2(
            (void *)addr_prepare,
            before_prepare,
            NULL,
            NULL);

    if (rc) {
        pr_info(
            "cam-ubwc: hook failed rc=%d\n",
            rc);
        return -1;
    }

    inject_mode = INJECT_OFF;
    pattern_mode = PATTERN_BAR;

    frame_counter = 0;
    inject_counter = 0;

    pr_info(
        "cam-ubwc: init ok\n");

    return 0;
}


/*
 * KPM control.
 */
static long cam_kpm_control0(
    const char *args,
    char __user *out_msg,
    int outlen)
{
    const char *reply;

    if (!args)
        return -1;

    reply = "ok";

    if (kp_streq(args, "start")) {

        inject_mode = INJECT_LOOP;

        reply = "started";

        pr_info(
            "cam-ubwc: start\n");

    } else if (kp_streq(args, "once")) {

        inject_mode = INJECT_ONCE;

        reply = "once";

        pr_info(
            "cam-ubwc: once\n");

    } else if (kp_streq(args, "stop")) {

        inject_mode = INJECT_OFF;

        reply = "stopped";

        pr_info(
            "cam-ubwc: stop\n");

    } else if (kp_streq(args, "black")) {

        pattern_mode = PATTERN_BLACK;

        reply = "black";

        pr_info(
            "cam-ubwc: pattern black\n");

    } else if (kp_streq(args, "white")) {

        pattern_mode = PATTERN_WHITE;

        reply = "white";

        pr_info(
            "cam-ubwc: pattern white\n");

    } else if (kp_streq(args, "hgrad")) {

        pattern_mode = PATTERN_HGRAD;

        reply = "hgrad";

        pr_info(
            "cam-ubwc: pattern hgrad\n");

    } else if (kp_streq(args, "vgrad")) {

        pattern_mode = PATTERN_VGRAD;

        reply = "vgrad";

        pr_info(
            "cam-ubwc: pattern vgrad\n");

    } else if (kp_streq(args, "bar")) {

        pattern_mode = PATTERN_BAR;

        reply = "bar";

        pr_info(
            "cam-ubwc: pattern bar\n");

    } else if (kp_streq(args, "reset")) {

        frame_counter = 0;
        inject_counter = 0;

        reply = "reset";

        pr_info(
            "cam-ubwc: reset\n");

    } else if (kp_streq(args, "status")) {

        pr_info(
            "cam-ubwc: STATUS "
            "mode=%d pattern=%d "
            "frame=%lu injected=%lu "
            "last=%ux%u "
            "Y=%u/%u "
            "UV=%u/%u\n",
            inject_mode,
            pattern_mode,
            frame_counter,
            inject_counter,
            last_width,
            last_height,
            last_stride_y,
            last_slice_y,
            last_stride_uv,
            last_slice_uv);

        reply = "status";

    } else {

        reply =
            "start once stop black white hgrad vgrad bar status reset";
    }

    if (out_msg && outlen > 0) {
        unsigned int n;

        n = kp_strlen(reply) + 1;

        if (n > (unsigned int)outlen)
            n = (unsigned int)outlen;

        compat_copy_to_user(
            out_msg,
            reply,
            n);
    }

    return 0;
}


/*
 * KPM exit.
 */
static long cam_kpm_exit(
    void *reserved)
{
    inject_mode = INJECT_OFF;

    if (addr_prepare)
        unhook(
            (void *)addr_prepare);

    pr_info(
        "cam-ubwc: exit\n");

    return 0;
}


KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
