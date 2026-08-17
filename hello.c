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
KPM_DESCRIPTION("RDI resource_type discovery - raw dump diagnostic");

static unsigned long addr_add_io_buffers;

static volatile char capture_status;   // 0=空闲 1=诊断中
static volatile unsigned int cnt_hook_before;
static volatile int dump_count;

#define MAX_DUMPS 3


static void before_add_io_buffers(hook_fargs3_t *args, void *udata)
{
    cnt_hook_before++;

    if (capture_status != 1)
        return;

    if (dump_count >= MAX_DUMPS)
        return;

    dump_count++;

    void *prepare = (void *)args->arg2;   // 第3个参数(0-indexed arg2)

    if (!prepare) {
        pr_info("cam-raw-dump: DUMP#%d prepare is NULL\n", dump_count);
        return;
    }

    pr_info("cam-raw-dump: DUMP#%d prepare=%p\n", dump_count, prepare);

    // 原样dump *prepare 前256字节(32个uint64),不假设任何字段布局
    uint64_t *raw = (uint64_t *)prepare;
    int i;

    for (i = 0; i < 32; i += 4) {
        pr_info("cam-raw-dump: prep[%02d-%02d] = %llx %llx %llx %llx\n",
                i, i+3, raw[i], raw[i+1], raw[i+2], raw[i+3]);
    }

    // 找出看起来像内核指针的值(高位是0xffffff开头),这些很可能是packet等结构体的地址
    pr_info("cam-raw-dump: DUMP#%d scanning for pointer-like values...\n", dump_count);
    for (i = 0; i < 32; i++) {
        uint64_t v = raw[i];
        if ((v & 0xffffff0000000000ULL) == 0xffffff0000000000ULL) {
            pr_info("cam-raw-dump: prep[%d] LOOKS LIKE KERNEL PTR = %llx\n", i, v);
        }
    }
}


static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    pr_info("cam-raw-dump: symbol lookup\n");

    addr_add_io_buffers =
        kallsyms_lookup_name("cam_isp_add_io_buffers");

    pr_info("cam-raw-dump: cam_isp_add_io_buffers addr=%lx\n", addr_add_io_buffers);

    if (!addr_add_io_buffers) {
        pr_err("cam-raw-dump: symbol lookup failed\n");
        return -1;
    }

    if (hook_wrap3(
        (void *)addr_add_io_buffers,
        before_add_io_buffers,
        NULL,
        NULL)) {

        pr_err("cam-raw-dump: hook add_io_buffers failed\n");
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
        dump_count = 0;

        pr_info("cam-raw-dump: control0 armed, diagnostic dump started\n");

        compat_copy_to_user(out_msg, "armed", 6);

    } else if (args[0] == 's') {

        capture_status = 0;

        pr_info("cam-raw-dump: stopped, hook_before=%u dump_count=%d\n",
                cnt_hook_before, dump_count);

        compat_copy_to_user(out_msg, "stopped", 8);
    }

    return 0;
}


static long cam_kpm_exit(void *reserved)
{
    if (addr_add_io_buffers)
        unhook((void *)addr_add_io_buffers);

    pr_info("cam-raw-dump exit\n");

    return 0;
}


KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
