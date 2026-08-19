#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.3.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("RDI dma-buf probe");

#define CAM_PACKET_MAX_PLANES 3
#define CAM_BUF_OUTPUT 2

#define RDI_0 0x3006
#define RDI_1 0x3007
#define RDI_2 0x3008
#define RDI_3 0x3009

#define HANDLE_IDX_MASK 0x7fff
#define HANDLE_FD_SHIFT 16

struct kp_cam_packet_header {
	unsigned int op_code;
	unsigned int size;
	unsigned long long request_id;
	unsigned int flags;
	unsigned int padding;
};

struct kp_cam_packet {
	struct kp_cam_packet_header header;
	unsigned int cmd_buf_offset;
	unsigned int num_cmd_buf;
	unsigned int io_configs_offset;
	unsigned int num_io_configs;
	unsigned int patch_offset;
	unsigned int num_patches;
	unsigned int kmd_cmd_buf_index;
	unsigned int kmd_cmd_buf_offset;
	unsigned long long payload[1];
};

struct kp_cam_plane_cfg {
	unsigned int v[12];
};

struct kp_cam_cmd_buf_desc {
	int mem_handle;
	unsigned int offset;
	unsigned int size;
	unsigned int length;
	unsigned int type;
	unsigned int meta_data;
};

struct kp_cam_buf_io_cfg {
	int mem_handle[3];
	unsigned int offsets[3];
	struct kp_cam_plane_cfg planes[3];
	unsigned int format;
	unsigned int color_space;
	unsigned int color_pattern;
	unsigned int bpp;
	unsigned int rotation;
	unsigned int resource_type;
	int fence;
	int early_fence;
	struct kp_cam_cmd_buf_desc aux_cmd_buf;
	unsigned int direction;
	unsigned int batch_size;
	unsigned int subsample_pattern;
	unsigned int subsample_period;
	unsigned int framedrop_pattern;
	unsigned int framedrop_period;
	unsigned int flag;
	unsigned int padding;
};

static unsigned long addr_prepare;
static unsigned long addr_dma_buf_get;
static unsigned long addr_dma_buf_put;

static void *(*get_dma_buf)(int fd);
static void (*put_dma_buf)(void *dmabuf);

static volatile int armed;
static volatile unsigned int hook_count;
static volatile unsigned int rdi_count;

#define MAX_RDI_LOG 8

static void before_prepare(hook_fargs2_t *args, void *udata)
{
	struct kp_cam_packet *packet;
	struct kp_cam_buf_io_cfg *io_cfg;
	unsigned int i, plane;
	unsigned int handle;
	unsigned int idx;
	unsigned int fd;
	void *dmabuf;

	hook_count++;

	if (!armed || rdi_count >= MAX_RDI_LOG)
		return;

	packet = *(struct kp_cam_packet **)args->arg1;
	if (!packet)
		return;

	if (!packet->num_io_configs ||
	    packet->num_io_configs > 64)
		return;

	io_cfg = (struct kp_cam_buf_io_cfg *)(
		(unsigned char *)packet->payload +
		packet->io_configs_offset);

	for (i = 0; i < packet->num_io_configs; i++) {
		if (io_cfg[i].direction != CAM_BUF_OUTPUT)
			continue;

		if (io_cfg[i].resource_type < RDI_0 ||
		    io_cfg[i].resource_type > RDI_3)
			continue;

		rdi_count++;

		pr_info(
			"cam-raw-dump: RDI res=0x%x req=%llu io=%u\n",
			io_cfg[i].resource_type,
			packet->header.request_id,
			i);

		for (plane = 0;
		     plane < CAM_PACKET_MAX_PLANES;
		     plane++) {
			if (!io_cfg[i].mem_handle[plane])
				break;

			handle = (unsigned int)io_cfg[i].mem_handle[plane];

			idx = handle & HANDLE_IDX_MASK;
			fd = handle >> HANDLE_FD_SHIFT;

			pr_info(
				"cam-raw-dump: RDI=0x%x plane=%u "
				"mem=0x%x idx=%u fd=%u\n",
				io_cfg[i].resource_type,
				plane,
				handle,
				idx,
				fd);

			if (!get_dma_buf)
				continue;

			dmabuf = get_dma_buf((int)fd);

			pr_info(
				"cam-raw-dump: RDI=0x%x plane=%u "
				"fd=%u dma_buf=%p\n",
				io_cfg[i].resource_type,
				plane,
				fd,
				dmabuf);

			if (dmabuf && put_dma_buf)
				put_dma_buf(dmabuf);
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
		kallsyms_lookup_name(
			"cam_ife_mgr_prepare_hw_update");

	addr_dma_buf_get =
		kallsyms_lookup_name("dma_buf_get");

	addr_dma_buf_put =
		kallsyms_lookup_name("dma_buf_put");

	pr_info(
		"cam-raw-dump: prepare=%lx dma_buf_get=%lx dma_buf_put=%lx\n",
		addr_prepare,
		addr_dma_buf_get,
		addr_dma_buf_put);

	if (!addr_prepare ||
	    !addr_dma_buf_get ||
	    !addr_dma_buf_put)
		return -1;

	get_dma_buf =
		(void *(*)(int))(void *)addr_dma_buf_get;

	put_dma_buf =
		(void (*)(void *))(void *)addr_dma_buf_put;

	if (hook_wrap2(
		(void *)addr_prepare,
		before_prepare,
		NULL,
		NULL))
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

		pr_info(
			"cam-raw-dump: stopped hooks=%u rdi=%u\n",
			hook_count,
			rdi_count);

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
