#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kputils.h>
#include <hook.h>

#include <cam_defs.h>
#include <cam_mem_mgr_api.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.0.2");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("RDI CPU buffer access test");

static unsigned long hook_addr;
static unsigned int log_count;

static void before_prepare(hook_fargs2_t *args, void *udata)
{
	struct cam_hw_prepare_update_args *prepare = args->arg1;
	struct cam_packet *packet;
	struct cam_buf_io_cfg *io_cfg;
	unsigned int i, j;

	if (!prepare || !prepare->packet)
		return;

	packet = prepare->packet;
	io_cfg = (struct cam_buf_io_cfg *)(
		(uint8_t *)&packet->payload + packet->io_configs_offset);

	for (i = 0; i < packet->num_io_configs; i++) {
		if (io_cfg[i].direction != CAM_BUF_OUTPUT)
			continue;

		if (io_cfg[i].resource_type < 0x3006 ||
		    io_cfg[i].resource_type > 0x3009)
			continue;

		if (log_count >= 20)
			return;

		for (j = 0; j < CAM_PACKET_MAX_PLANES; j++) {
			uintptr_t vaddr;
			size_t len;
			int rc;

			if (!io_cfg[i].mem_handle[j])
				break;

			rc = cam_mem_get_cpu_buf(
				io_cfg[i].mem_handle[j],
				&vaddr, &len);

			pr_info(
				"cam-raw-dump: RDI res=0x%x plane=%u "
				"handle=0x%x rc=%d vaddr=%px len=%zu req=%llu\n",
				io_cfg[i].resource_type,
				j,
				io_cfg[i].mem_handle[j],
				rc,
				(void *)vaddr,
				len,
				packet->header.request_id);

			log_count++;
		}
	}
}

static long cam_kpm_init(
	const char *args,
	const char *event,
	void *reserved)
{
	hook_addr = kallsyms_lookup_name(
		"cam_ife_mgr_prepare_hw_update");

	if (!hook_addr)
		return -1;

	if (hook_wrap2(
		(void *)hook_addr,
		before_prepare,
		NULL,
		NULL))
		return -1;

	pr_info("cam-raw-dump: init ok addr=%lx\n", hook_addr);
	return 0;
}

static long cam_kpm_exit(void *reserved)
{
	if (hook_addr)
		unhook((void *)hook_addr);

	pr_info("cam-raw-dump: exit logs=%u\n", log_count);
	return 0;
}

KPM_INIT(cam_kpm_init);
KPM_EXIT(cam_kpm_exit);
