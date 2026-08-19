#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.0.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("IFE prepare_hw_update diagnostic");

static unsigned long addr_prepare;
static volatile unsigned int hook_count;

static void before_prepare(hook_fargs2_t *args, void *udata)
{
	hook_count++;

	if (hook_count <= 10)
		pr_info("cam-raw-dump: prepare_hw_update #%u hw_mgr=%p prepare=%p\n",
			hook_count, (void *)args->arg0, (void *)args->arg1);
}

static long cam_kpm_init(const char *args, const char *event, void *reserved)
{
	addr_prepare = kallsyms_lookup_name("cam_ife_mgr_prepare_hw_update");

	pr_info("cam-raw-dump: prepare_hw_update addr=%lx\n", addr_prepare);

	if (!addr_prepare)
		return -1;

	if (hook_wrap2((void *)addr_prepare, before_prepare, NULL, NULL))
		return -1;

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

	if (args[0] == 's') {
		pr_info("cam-raw-dump: hook_count=%u\n", hook_count);
		compat_copy_to_user(out_msg, "stopped", 8);
	}

	return 0;
}

static long cam_kpm_exit(void *reserved)
{
	if (addr_prepare)
		unhook((void *)addr_prepare);

	pr_info("cam-raw-dump: exit\n");
	return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
