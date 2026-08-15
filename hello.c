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
KPM_DESCRIPTION("Camera RDI raw data extractor - size distribution analysis");

#define O_WRONLY 00000001
#define O_CREAT  00000100
#define O_TRUNC  00001000

#define FRAME_BUF_SIZE (2 * 1024 * 1024)

static unsigned char cached_frame[FRAME_BUF_SIZE];
static volatile size_t cached_len;

static void *(*p_filp_open)(const char *, int, unsigned short);
static long (*p_kernel_write)(void *, const void *, unsigned long, long long *);
static int (*p_filp_close)(void *, void *);
static int (*p_cam_mem_get_cpu_buf)(int32_t, uintptr_t *, size_t *);

static unsigned long addr_get_io_buf;

static volatile char capture_status;   // 0=空闲 1=统计尺寸分布 2=已拷贝待写盘 3=已写盘

static volatile unsigned int cnt_hookA_before;
static volatile unsigned int cnt_hookA_after;

// ===== 统计不同尺寸出现的次数,最多记录32种不同尺寸 =====
#define MAX_DISTINCT_SIZES 32
struct size_stat { size_t len; unsigned int count; };
static struct size_stat size_stats[MAX_DISTINCT_SIZES];
static volatile int distinct_count;

// 用户手动指定"就是这个尺寸"之后,才真正抓取拷贝
static volatile size_t target_len;


static int is_err_ptr(void *ptr)
{
    return (unsigned long)ptr >= (unsigned long)-4095;
}


static void record_size_stat(size_t len)
{
    int i;
    for (i = 0; i < distinct_count; i++) {
        if (size_stats[i].len == len) {
            size_stats[i].count++;
            return;
        }
    }
    if (distinct_count < MAX_DISTINCT_SIZES) {
        size_stats[distinct_count].len = len;
        size_stats[distinct_count].count = 1;
        distinct_count++;
    }
}


static void before_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_before++;
    args->local.data0 = args->arg0;
}


static void after_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_after++;

    if (capture_status == 0)
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

    // 模式1:纯统计尺寸分布,不拷贝
    if (capture_status == 1) {
        record_size_stat(len);
        return;
    }

    // 模式2:用户已经指定了target_len,只抓这个精确尺寸的buffer
    if (capture_status == 2 && len == target_len) {
        size_t copy_len = len > FRAME_BUF_SIZE ? FRAME_BUF_SIZE : len;
        memcpy(cached_frame, (void *)vaddr, copy_len);
        cached_len = copy_len;
        capture_status = 3;
        pr_info("cam-raw-dump: target frame captured! handle=%d len=%zu\n",
                buf_handle, len);
    }
}


static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    pr_info("cam-raw-dump: symbol lookup\n");

    p_filp_open = (void *)kallsyms_lookup_name("filp_open");
    p_kernel_write = (void *)kallsyms_lookup_name("kernel_write");
    p_filp_close = (void *)kallsyms_lookup_name("filp_close");
    p_cam_mem_get_cpu_buf = (void *)kallsyms_lookup_name("cam_mem_get_cpu_buf");
    addr_get_io_buf = kallsyms_lookup_name("cam_mem_get_io_buf");

    if (!p_filp_open || !p_kernel_write || !p_filp_close ||
        !p_cam_mem_get_cpu_buf || !addr_get_io_buf) {
        pr_err("cam-raw-dump: symbol lookup failed\n");
        return -1;
    }

    if (hook_wrap3((void *)addr_get_io_buf, before_get_io_buf, after_get_io_buf, NULL)) {
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

    void *f = p_filp_open("/data/local/tmp/cam_frame.raw",
                           O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (is_err_ptr(f)) {
        pr_err("cam-raw-dump: open failed\n");
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
        // 进入统计模式,清空之前的统计
        distinct_count = 0;
        memset((void *)size_stats, 0, sizeof(size_stats));
        capture_status = 1;
        pr_info("cam-raw-dump: entering STAT mode\n");
        compat_copy_to_user(out_msg, "stat_mode", 10);

    } else if (args[0] == 'd') {
        // dump统计结果:所有见过的不同尺寸及出现次数
        int i;
        pr_info("cam-raw-dump: ===== size distribution (distinct=%d) =====\n", distinct_count);
        for (i = 0; i < distinct_count; i++) {
            pr_info("cam-raw-dump: size[%d] len=%zu count=%u\n",
                    i, size_stats[i].len, size_stats[i].count);
        }
        compat_copy_to_user(out_msg, "dumped", 7);

    } else if (args[0] == 't') {
        // 参数格式: t<数字>  指定目标尺寸,进入精确抓取模式
        // 例如输入 t65536 表示只抓 len==65536 的buffer
        target_len = 0;
        int i = 1;
        while (args[i] >= '0' && args[i] <= '9') {
            target_len = target_len * 10 + (args[i] - '0');
            i++;
        }
        capture_status = 2;
        pr_info("cam-raw-dump: target_len set to %zu, entering CAPTURE mode\n", target_len);
        compat_copy_to_user(out_msg, "target_set", 11);

    } else if (args[0] == 'w') {
        int rc = write_cached_frame_to_disk();
        compat_copy_to_user(out_msg, rc == 0 ? "write_ok" : "write_fail", 12);

    } else if (args[0] == 's') {
        pr_info("cam-raw-dump: status=%d hookA_before=%u hookA_after=%u "
                "distinct=%d cached_len=%zu target_len=%zu\n",
                capture_status, cnt_hookA_before, cnt_hookA_after,
                distinct_count, cached_len, target_len);

        char buf[16] = "status=";
        buf[7] = '0' + capture_status;
        buf[8] = '\0';
        compat_copy_to_user(out_msg, buf, 9);
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
