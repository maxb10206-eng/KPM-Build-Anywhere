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
KPM_DESCRIPTION("Camera RDI raw data extractor - arg1 sampling");

static int (*p_cam_mem_get_cpu_buf)(int32_t, uintptr_t *, size_t *);
static unsigned long addr_get_io_buf;

static volatile char capture_status;   // 0=空闲 1=采样中
static volatile unsigned int cnt_hookA_before;
static volatile unsigned int cnt_hookA_after;

#define MAX_LOG_ENTRIES 40
static volatile int log_count;


static void before_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_before++;
    args->local.data0 = args->arg0;
    args->local.data1 = args->arg1;   // 新增:把arg1也暂存下来
}


static void after_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_after++;

    if (capture_status != 1)
        return;

    int32_t buf_handle = (int32_t)args->local.data0;
    uint64_t raw_arg1 = (uint64_t)args->local.data1;

    if (!buf_handle || !p_cam_mem_get_cpu_buf)
        return;

    uintptr_t vaddr = 0;
    size_t len = 0;

    if (p_cam_mem_get_cpu_buf(buf_handle, &vaddr, &len))
        return;

    if (!vaddr || !len)
        return;

    // 只要大于4KB(排除掉过小的垃圾调用)就记录,不做其他过滤
    if (len > 4096 && log_count < MAX_LOG_ENTRIES) {
        log_count++;
        pr_info("cam-raw-dump: SAMPLE#%d handle=%d arg1=%llx len=%zu\n",
                log_count, buf_handle, raw_arg1, len);
    }
}


static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    pr_info("cam-raw-dump: symbol lookup\n");

    p_cam_mem_get_cpu_buf =
        (void *)kallsyms_lookup_name("cam_mem_get_cpu_buf");

    addr_get_io_buf =
        kallsyms_lookup_name("cam_mem_get_io_buf");

    if (!p_cam_mem_get_cpu_buf || !addr_get_io_buf) {
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
        log_count = 0;

        pr_info("cam-raw-dump: control0 armed, sampling started\n");

        compat_copy_to_user(out_msg, "armed", 6);

    } else if (args[0] == 's') {

        capture_status = 0;  // 停止采样

        pr_info("cam-raw-dump: stopped, hookA_before=%u hookA_after=%u log_count=%d\n",
                cnt_hookA_before, cnt_hookA_after, log_count);

        char buf[16] = "logs=";
        buf[5] = '0' + (log_count / 10);
        buf[6] = '0' + (log_count % 10);
        buf[7] = '\0';

        compat_copy_to_user(out_msg, buf, 8);
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
