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
KPM_DESCRIPTION("Camera RDI raw data extractor - vmalloc based");

#define O_WRONLY 00000001
#define O_CREAT  00000100
#define O_TRUNC  00001000

#define DYNAMIC_BUF_SIZE (8 * 1024 * 1024)
#define SIZE_THRESHOLD (1 * 1024 * 1024)
#define TARGET_ARG1 0x2a161

static void *(*p_filp_open)(const char *, int, unsigned short);
static long (*p_kernel_write)(void *, const void *, unsigned long, long long *);
static int (*p_filp_close)(void *, void *);
static int (*p_cam_mem_get_cpu_buf)(int32_t, uintptr_t *, size_t *);
static void *(*p_vmalloc)(unsigned long size);
static void (*p_vfree)(const void *addr);

static unsigned char *dyn_buf;
static volatile size_t cached_len;

static unsigned long addr_get_io_buf;

static volatile char capture_status;

static volatile unsigned int cnt_hookA_before;
static volatile unsigned int cnt_hookA_after;
static volatile unsigned int cnt_too_small;
static volatile unsigned int cnt_too_big;
static volatile unsigned int cnt_copy_ok;

static volatile size_t max_len_seen;


static int is_err_ptr(void *ptr)
{
    return (unsigned long)ptr >= (unsigned long)-4095;
}


static void before_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_before++;
    args->local.data0 = args->arg0;
    args->local.data1 = args->arg1;
}


static void after_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_after++;

    if (capture_status != 1)
        return;

    int32_t buf_handle = (int32_t)args->local.data0;
    uint64_t raw_arg1 = (uint64_t)args->local.data1;

    if (!buf_handle || !p_cam_mem_get_cpu_buf || !dyn_buf)
        return;

    if (raw_arg1 != TARGET_ARG1)
        return;

    uintptr_t vaddr = 0;
    size_t len = 0;

    if (p_cam_mem_get_cpu_buf(buf_handle, &vaddr, &len))
        return;

    if (!vaddr || !len)
        return;

    if (len > max_len_seen)
        max_len_seen = len;

    if (len < SIZE_THRESHOLD) {
        cnt_too_small++;
        return;
    }

    if (len > DYNAMIC_BUF_SIZE) {
        cnt_too_big++;
        return;
    }

    memcpy(dyn_buf, (void *)vaddr, len);
    cached_len = len;

    cnt_copy_ok++;
    capture_status = 2;

    pr_info("cam-raw-dump: TARGET frame copied! handle=%d arg1=%llx len=%zu\n",
            buf_handle, raw_arg1, len);
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

    // 换成标准内核vmalloc/vfree,而不是kp_malloc
    p_vmalloc =
        (void *)kallsyms_lookup_name("vmalloc");

    p_vfree =
        (void *)kallsyms_lookup_name("vfree");

    pr_info("cam-raw-dump: vmalloc=%p vfree=%p\n", p_vmalloc, p_vfree);

    if (!p_filp_open ||
        !p_kernel_write ||
        !p_filp_close ||
        !p_cam_mem_get_cpu_buf ||
        !addr_get_io_buf ||
        !p_vmalloc ||
        !p_vfree) {

        pr_err("cam-raw-dump: symbol lookup failed\n");
        return -1;
    }

    dyn_buf = p_vmalloc(DYNAMIC_BUF_SIZE);

    pr_info("cam-raw-dump: dyn_buf=%p size=%d\n", dyn_buf, DYNAMIC_BUF_SIZE);

    if (!dyn_buf) {
        pr_err("cam-raw-dump: vmalloc failed\n");
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
    if (cached_len == 0 || !dyn_buf)
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
    long written = p_kernel_write(f, dyn_buf, cached_len, &pos);

    p_filp_close(f, NULL);

    pr_info("cam-raw-dump: written=%ld to disk (target was %zu)\n",
            written, cached_len);

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
                "too_small=%u too_big=%u copy_ok=%u cached_len=%zu max_len_seen=%zu\n",
                capture_status, cnt_hookA_before, cnt_hookA_after,
                cnt_too_small, cnt_too_big, cnt_copy_ok, cached_len, max_len_seen);

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

    if (dyn_buf && p_vfree)
        p_vfree(dyn_buf);

    pr_info("cam-raw-dump exit\n");

    return 0;
}


KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
