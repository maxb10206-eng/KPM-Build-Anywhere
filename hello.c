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
KPM_DESCRIPTION("Camera RDI raw data extractor via cam_mem_get_io_buf hook");

#define O_WRONLY 00000001
#define O_CREAT  00000100
#define O_TRUNC  00001000

#define CHUNK_SIZE (2 * 1024 * 1024)

static unsigned char chunk_buf[CHUNK_SIZE];

static void *(*p_filp_open)(const char *, int, unsigned short);
static long (*p_kernel_write)(void *, const void *, unsigned long, long long *);
static int (*p_filp_close)(void *, void *);
static int (*p_cam_mem_get_cpu_buf)(int32_t, uintptr_t *, size_t *);

static unsigned long addr_get_io_buf;

static volatile char capture_status;   // 0=空闲 1=武装 2=完成

static volatile unsigned int cnt_hookA_before;
static volatile unsigned int cnt_hookA_after;
static volatile unsigned int cnt_write_attempt;
static volatile unsigned int cnt_write_fail;
static volatile unsigned int cnt_write_ok;


static int is_err_ptr(void *ptr)
{
    return (unsigned long)ptr >= (unsigned long)-4095;
}


// ===== Hook: cam_mem_get_io_buf =====
// before阶段暂存 buf_handle(第一个参数)
static void before_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_before++;
    args->local.data0 = args->arg0;
}

// after阶段:如果处于武装状态,直接拿这个buf_handle尝试抓取写文件
static void after_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_after++;

    if (capture_status != 1)
        return;

    int32_t buf_handle = (int32_t)args->local.data0;

    if (!buf_handle || !p_cam_mem_get_cpu_buf)
        return;

    cnt_write_attempt++;

    uintptr_t vaddr = 0;
    size_t len = 0;

    if (p_cam_mem_get_cpu_buf(buf_handle, &vaddr, &len)) {
        cnt_write_fail++;
        return;
    }

    if (!vaddr || !len) {
        cnt_write_fail++;
        return;
    }

    void *f = p_filp_open(
        "/data/local/tmp/cam_frame.raw",
        O_CREAT | O_WRONLY | O_TRUNC,
        0644
    );

    if (is_err_ptr(f)) {
        cnt_write_fail++;
        pr_err("cam-raw-dump: open failed\n");
        return;
    }

    long long pos = 0;
    size_t remain = len;
    uintptr_t src = vaddr;

    while (remain) {
        size_t n = remain > CHUNK_SIZE ? CHUNK_SIZE : remain;

        memcpy(chunk_buf, (void *)src, n);

        if (p_kernel_write(f, chunk_buf, n, &pos) < 0)
            break;

        src += n;
        remain -= n;
    }

    p_filp_close(f, NULL);

    cnt_write_ok++;
    capture_status = 2;  // 抓到一次就停,避免连续覆盖

    pr_info("cam-raw-dump: frame written, handle=%d vaddr=%lx len=%zu\n",
            buf_handle, vaddr, len);
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


static long cam_kpm_control0(
    const char *args,
    char __user *out_msg,
    int outlen)
{
    if (!args)
        return -1;

    if (args[0] == 'c') {

        capture_status = 1;

        pr_info("cam-raw-dump: control0 armed, capture_status=%d\n", capture_status);

        compat_copy_to_user(
            out_msg,
            "armed",
            6
        );

    } else if (args[0] == 's') {

        pr_info("cam-raw-dump: status=%d hookA_before=%u hookA_after=%u "
                "write_attempt=%u write_ok=%u write_fail=%u\n",
                capture_status, cnt_hookA_before, cnt_hookA_after,
                cnt_write_attempt, cnt_write_ok, cnt_write_fail);

        char buf[16] = "status=";

        buf[7] = '0' + capture_status;
        buf[8] = '\0';

        compat_copy_to_user(
            out_msg,
            buf,
            9
        );
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
