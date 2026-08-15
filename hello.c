#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Camera RDI raw data extractor - size filtered");

#define O_WRONLY 00000001
#define O_CREAT  00000100
#define O_TRUNC  00001000

#define FRAME_BUF_SIZE (2 * 1024 * 1024)
#define SIZE_THRESHOLD  (3 * 1024 * 1024)   // 只抓超过512KB的buffer

static unsigned char cached_frame[FRAME_BUF_SIZE];
static volatile size_t cached_len;

static void *(*p_filp_open)(const char *, int, unsigned short);
static long (*p_kernel_write)(void *, const void *, unsigned long, long long *);
static int (*p_filp_close)(void *, void *);
static int (*p_cam_mem_get_cpu_buf)(int32_t, uintptr_t *, size_t *);

static unsigned long addr_get_io_buf;

static volatile char capture_status;   // 0=空闲 1=武装 2=已拷贝待写盘 3=已写盘完成

static volatile unsigned int cnt_hookA_before;
static volatile unsigned int cnt_hookA_after;
static volatile unsigned int cnt_seen_small;   // 见过但小于阈值,被跳过的次数
static volatile unsigned int cnt_copy_ok;

// 记录见过的最大几个len值,方便事后查看尺寸分布
#define LEN_HISTORY_SIZE 16
static volatile size_t len_history[LEN_HISTORY_SIZE];
static volatile int len_history_idx;
static volatile size_t max_len_seen;


static int is_err_ptr(void *ptr)
{
    return (unsigned long)ptr >= (unsigned long)-4095;
}


static void before_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_before++;
    args->local.data0 = args->arg0;
}


static void after_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_after++;

    if (capture_status != 1)
        return;

    int32_t buf_handle = (int32_t)args->local.data0;

    if (!buf_handle || !p_cam_mem_get_cpu_buf)
        return;

    uintptr_t vaddr = 0;
    size_t len = 0;

    if (p_cam_mem_get_cpu_buf(buf_handle, &vaddr, &len))
        return;

    if (!vaddr || !len)
        return;

    // 记录最大值,方便事后判断真实图像帧大概有多大
    if (len > max_len_seen)
        max_len_seen = len;

    // 记录到循环历史缓冲区
    len_history[len_history_idx] = len;
    len_history_idx = (len_history_idx + 1) % LEN_HISTORY_SIZE;

    // ===== 核心过滤逻辑:小于阈值直接跳过 =====
    if (len < SIZE_THRESHOLD) {
        cnt_seen_small++;
        return;
    }

    size_t copy_len = len > FRAME_BUF_SIZE ? FRAME_BUF_SIZE : len;

    memcpy(cached_frame, (void *)vaddr, copy_len);
    cached_len = copy_len;

    cnt_copy_ok++;
    capture_status = 2;

    pr_info("cam-raw-dump: LARGE frame copied! handle=%d len=%zu\n",
            buf_handle, len);
}


static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    pr_info("cam-raw-dump: symbol lookup\n");

    p_filp_open =
        (void *)kallsyms_lookup_name("filp_open");

    p_kernel_write =
        (void *)kallsyms_lookup_name("kernel_write");

    p_filp_close =
        (void *)kallsyms_lookup_name("filp_close");

    p_cam_mem_get_cpu_buf =
        (void *)kallsyms_lookup_name("cam_mem_get_cpu_buf");

    addr_get_io_buf =
        kallsyms_lookup_name("cam_mem_get_io_buf");

    if (!p_filp_open ||
        !p_kernel_write ||
        !p_filp_close ||
        !p_cam_mem_get_cpu_buf ||
        !addr_get_io_buf) {

        pr_err("cam-raw-dump: symbol lookup failed\n");
        return -1;
    }

    if (hook_wrap3(
        (void *)addr_get_io_buf,
        before_get_io_buf,
        after_get_io_buf,
        NULL)) {

        pr_err("cam-raw-dump: hook io buf failed\n");
        return -1;
    }

    pr_info("cam-raw-dump: init ok\n");

    return 0;
}


static int write_cached_frame_to_disk(void)
{
    if (cached_len == 0)
        return -1;

    void *f = p_filp_open(
        "/data/local/tmp/cam_frame.raw",
        O_CREAT | O_WRONLY | O_TRUNC,
        0644
    );

    if (is_err_ptr(f)) {
        pr_err("cam-raw-dump: open failed in control0 context\n");
        return -1;
    }

    long long pos = 0;
    long written = p_kernel_write(f, cached_frame, cached_len, &pos);

    p_filp_close(f, NULL);

    pr_info("cam-raw-dump: written=%ld to disk\n", written);

    return (written == (long)cached_len) ? 0 : -1;
}


static long cam_kpm_control0(
    const char *args,
    char __user *out_msg,
    int outlen)
{
    if (!args)
        return -1;

    if (args[0] == 'c') {

        capture_status = 1;
        cached_len = 0;

        pr_info("cam-raw-dump: control0 armed\n");

        compat_copy_to_user(out_msg, "armed", 6);

    } else if (args[0] == 'w') {

        int rc = write_cached_frame_to_disk();

        if (rc == 0) {
            capture_status = 3;
            compat_copy_to_user(out_msg, "write_ok", 9);
        } else {
            compat_copy_to_user(out_msg, "write_fail", 11);
        }

    } else if (args[0] == 's') {

        pr_info("cam-raw-dump: status=%d hookA_before=%u hookA_after=%u "
                "seen_small=%u copy_ok=%u cached_len=%zu max_len_seen=%zu\n",
                capture_status, cnt_hookA_before, cnt_hookA_after,
                cnt_seen_small, cnt_copy_ok, cached_len, max_len_seen);

        char buf[16] = "status=";
        buf[7] = '0' + capture_status;
        buf[8] = '\0';

        compat_copy_to_user(out_msg, buf, 9);

    } else if (args[0] == 'l') {

        // 打印最近记录的len历史,查看尺寸分布
        int i;
        pr_info("cam-raw-dump: len_history dump:\n");
        for (i = 0; i < LEN_HISTORY_SIZE; i++) {
            pr_info("cam-raw-dump: len_history[%d] = %zu\n", i, len_history[i]);
        }

        compat_copy_to_user(out_msg, "logged", 7);
    }

    return 0;
}


static long cam_kpm_exit(void *reserved)
{
    if (addr_get_io_buf)
        unhook((void *)addr_get_io_buf);

    pr_info("cam-raw-dump exit\n");

    return 0;
}


KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
