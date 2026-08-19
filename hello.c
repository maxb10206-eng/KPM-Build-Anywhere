#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <kputils.h>
#include <hook.h>
#include <camera/media/cam_defs.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.0.2");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("RDI CPU buffer mapping test");

#define RDI0 0x3006
#define RDI3 0x3009

typedef int (*get_cpu_buf_t)(int32_t, uintptr_t *, size_t *);

static unsigned long addr_prepare;
static get_cpu_buf_t get_cpu_buf;
static unsigned int hit_count;

struct prepare_min {
	void *packet;
};

static void before_prepare(hook_fargs2_t *args, void *udata)
{
	struct prepare_min *p = (void *)args->arg1;
	struct cam_packet *packet;
	struct cam_buf_io_cfg *io_cfg;
	uintptr_t vaddr;
	size_t len;
	int i, j, rc;

	if (!p || !p->packet)
		return;

	packet = p->packet;
	io_cfg = (struct cam_buf_io_cfg *)
		((uint8_t *)&packet->payload + packet->io_configs_offset);

	for (i = 0; i < packet->num_io_configs; i++) {
		if (io_cfg[i].direction != CAM_BUF_OUTPUT)
			continue;

		if (io_cfg[i].resource_type < RDI0 ||
		    io_cfg[i].resource_type > RDI3)
			continue;

		for (j = 0; j < CAM_PACKET_MAX_PLANES; j++) {
			if (!io_cfg[i].mem_handle[j])
				break;

			vaddr = 0;
			len = 0;
			rc = get_cpu_buf ?
				get_cpu_buf(io_cfg[i].mem_handle[j],
					&vaddr, &len) : -ENOSYS;

			if (hit_count++ < 10)
				pr_info("cam-raw-dump: RDI=0x%x plane=%d mem=0x%x rc=%d vaddr=%px len=%zu\n",
					io_cfg[i].resource_type, j,
					io_cfg[i].mem_handle[j], rc,
					(void *)vaddr, len);
		}
	}
}

static long cam_kpm_init(const char *args,
	const char *event, void *reserved)
{
	addr_prepare =
		kallsyms_lookup_name("cam_ife_mgr_prepare_hw_update");
	get_cpu_buf =
		(get_cpu_buf_t)kallsyms_lookup_name("cam_mem_get_cpu_buf");

	pr_info("cam-raw-dump: prepare=%lx cpu_buf=%lx\n",
		addr_prepare, (unsigned long)get_cpu_buf);

	if (!addr_prepare || !get_cpu_buf)
		return -1;

	if (hook_wrap2((void *)addr_prepare,
		before_prepare, NULL, NULL))
		return -1;

	return 0;
}

static long cam_kpm_control0(const char *args,
	char __user *out_msg, int outlen)
{
	if (args && args[0] == 's')
		pr_info("cam-raw-dump: hits=%u\n", hit_count);
	return 0;
}

static long cam_kpm_exit(void *reserved)
{
	if (addr_prepare)
		unhook((void *)addr_prepare);
	return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
