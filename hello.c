#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <kputils.h>
#include <hook.h>

#include <camera/media/cam_defs.h>
#include <cam_core/cam_hw_mgr_intf.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("RDI CPU buffer probe");

static unsigned long addr_prepare;
static int (*get_cpu_buf)(int32_t, uintptr_t *, size_t *);

static volatile int armed;
static volatile unsigned int hook_count;
static volatile unsigned int rdi_count;

#define MAX_RDI_LOG 8

static void before_prepare(hook_fargs2_t *args, void *udata)
{
	struct cam_hw_prepare_update_args *prepare;
	struct cam_packet *packet;
	struct cam_buf_io_cfg *io_cfg;
	unsigned int i, plane;
	uintptr_t vaddr;
	size_t len;
	int rc;

	hook_count++;

	if (!armed || rdi_count >= MAX_RDI_LOG)
		return;

	prepare = (struct cam_hw_prepare_update_args *)args->arg1;
	if (!prepare || !prepare->packet)
		return;

	packet = prepare->packet;

	io_cfg = (struct cam_buf_io_cfg *)((uint8_t *)&packet->payload +
					   packet->io_configs_offset);

	for (i = 0; i < packet->num_io_configs; i++) {
		if (io_cfg[i].direction != CAM_BUF_OUTPUT)
			continue;

		if (io_cfg[i].resource_type < 0x3006 ||
		    io_cfg[i].resource_type > 0x3009)
			continue;

		rdi_count++;

		pr_info("cam-raw-dump: RDI res=0x%x req=%llu\n",
			io_cfg[i].resource_type,
			packet->header.request_id);

		for (plane = 0; plane < CAM_PACKET_MAX_PLANES; plane++) {
			if (!io_cfg[i].mem_handle[plane])
				break;

			vaddr = 0;
			len = 0;

			rc = get_cpu_buf ?
				get_cpu_buf(io_cfg[i].mem_handle[plane],
					    &vaddr, &len) : -ENOSYS;

			pr_info("cam-raw-dump: RDI res=0x%x plane=%u "
				"mem=0x%x rc=%d vaddr=%px len=%zu\n",
				io_cfg[i].resource_type,
				plane,
				io_cfg[i].mem_handle[plane],
				rc,
				(void *)vaddr,
				len);
		}

		if (rdi_count >= MAX_RDI_LOG)
			break;
	}
}

static long cam_kpm_init(
	const char *args,
	const char *event,
	void *reserved)
{
	addr_prepare =
		kallsyms_lookup_name("cam_ife_mgr_prepare_hw_update");

	get_cpu_buf =
		(void *)kallsyms_lookup_name("cam_mem_get_cpu_buf");

	pr_info("cam-raw-dump: prepare=%lx cpu_buf=%lx\n",
		addr_prepare, (unsigned long)get_cpu_buf);

	if (!addr_prepare || !get_cpu_buf)
		return -1;

	if (hook_wrap2((void *)addr_prepare,
		       before_prepare, NULL, NULL))
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

	if (args[0] == 'c') {
		armed = 1;
		rdi_count = 0;
		pr_info("cam-raw-dump: armed\n");
		compat_copy_to_user(out_msg, "armed", 6);
	} else if (args[0] == 's') {
		armed = 0;
		pr_info("cam-raw-dump: stopped hooks=%u rdi=%u\n",
			hook_count, rdi_count);
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
