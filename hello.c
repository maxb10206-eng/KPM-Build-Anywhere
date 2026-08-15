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
KPM_DESCRIPTION("Camera RDI raw data extractor - safe context split");

#define O_WRONLY 00000001
#define O_CREAT  00000100
#define O_TRUNC  00001000

#define CHUNK_SIZE (2 * 1024 * 1024)

static unsigned char cached_frame[CHUNK_SIZE];
static volatile size_t cached_len;

static void *(*p_filp_open)(const char *, int, unsigned short);
static long (*p_kernel_write)(void *, const void *, unsigned long, long long *);
static int (*p_filp_close)(void *, void *);
static int (*p_cam_mem_get_cpu_buf)(int32_t, uintptr_t *, size_t *);

static unsigned long addr_get_io_buf;

static volatile char capture_status;   // 0=空闲 1=武装 2=已拷贝待写盘 3=已写盘完成

static volatile unsigned int cnt_hookA_before;
static volatile unsigned int cnt_hookA_after;
static volatile unsigned int cnt_copy_ok;


static int is_err_ptr(void *ptr)
{
    return (unsigned long)ptr >= (unsigned long)-4095;
}


// ===== Hook: cam_mem_get_io_buf =====
// 只做memcpy,不碰文件I/O,安全留在原子上下文
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

    size_t copy_len = len > CHUNK_SIZE ? CHUNK_SIZE : len;

    memcpy(cached_frame, (void *)vaddr, copy_len);
    cached_len = copy_len;

    cnt_copy_ok++;
    capture_status = 2;  // 拷贝完成,等待用户态触发写盘

    pr_info("cam-raw-dump: frame copied to buffer, handle=%d len=%zu\n",
            buf_handle, copy_len);
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


// 真正的写盘操作,只在这里(用户态触发的进程上下文)执行
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

        // 触发写盘,这里是进程上下文,安全
        int rc = write_cached_frame_to_disk();

        if (rc == 0) {
            capture_status = 3;
            compat_copy_to_user(out_msg, "write_ok", 9);
        } else {
            compat_copy_to_user(out_msg, "write_fail", 11);
        }

    } else if (args[0] == 's') {

        pr_info("cam-raw-dump: status=%d hookA_before=%u hookA_after=%u "
                "copy_ok=%u cached_len=%zu\n",
                capture_status, cnt_hookA_before, cnt_hookA_after,
                cnt_copy_ok, cached_len);

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
