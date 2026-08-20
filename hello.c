#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.5.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("RDI0 buffer-done verification");

#define CAM_BUF_OUTPUT 2
#define RDI_0 0x3006
#define MAX_RES 32

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
	unsigned int width;
	unsigned int height;
	unsigned int plane_stride;
	unsigned int slice_height;
	unsigned int meta_stride;
	unsigned int meta_size;
	unsigned int meta_offset;
	unsigned int packer_config;
	unsigned int mode_config;
	unsigned int tile_config;
	unsigned int h_init;
	unsigned int v_init;
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

/*
 * cam_isp_hw_event_info
 *
 * enum cam_isp_resource_type  : u32
 * bool is_secondary_evt       : u8
 * 3 bytes padding
 * uint32_t res_id
 * uint32_t hw_idx
 * uint32_t reg_val
 * uint32_t hw_type
 * uint32_t in_core_idx
 * void *event_data
 */
struct kp_cam_isp_hw_event_info {
	unsigned int res_type;
	unsigned char is_secondary_evt;
	unsigned char reserved[3];
	unsigned int res_id;
	unsigned int hw_idx;
	unsigned int reg_val;
	unsigned int hw_type;
	unsigned int in_core_idx;
	void *event_data;
};

/*
 * cam_isp_hw_compdone_event_info
 */
struct kp_cam_isp_hw_compdone_event_info {
	unsigned int num_res;
	unsigned int res_id[MAX_RES];
	unsigned int last_consumed_addr[MAX_RES];
};

static unsigned long addr_prepare;
static unsigned long addr_buf_done;

static volatile int armed;

static volatile unsigned int prepare_count;
static volatile unsigned int done_count;
static volatile unsigned int rdi_done_count;

static volatile int last_rdi_fd;
static volatile unsigned int last_rdi_handle;
static volatile unsigned long long last_rdi_request;

static void before_prepare(
	hook_fargs2_t *args,
	void *udata)
{
	struct kp_cam_packet *packet;
	struct kp_cam_buf_io_cfg *io_cfg;
	unsigned int i;

	if (!armed)
		return;

	packet =
		*(struct kp_cam_packet **)args->arg1;

	if (!packet)
		return;

	if (!packet->num_io_configs ||
	    packet->num_io_configs > 64)
		return;

	io_cfg =
		(struct kp_cam_buf_io_cfg *)(
			(unsigned char *)packet->payload +
			packet->io_configs_offset);

	for (i = 0;
	     i < packet->num_io_configs;
	     i++) {

		if (io_cfg[i].direction != CAM_BUF_OUTPUT)
			continue;

		if (io_cfg[i].resource_type != RDI_0)
			continue;

		if (!io_cfg[i].mem_handle[0])
			continue;

		last_rdi_handle =
			(unsigned int)
			io_cfg[i].mem_handle[0];

		last_rdi_fd =
			(int)(
				last_rdi_handle >> 16);

		last_rdi_request =
			packet->header.request_id;

		prepare_count++;

		pr_info(
			"cam-raw-dump: PREP RDI0 "
			"req=%llu mem=0x%x fd=%d\n",
			last_rdi_request,
			last_rdi_handle,
			last_rdi_fd);

		return;
	}
}

static void before_buf_done(
	hook_fargs2_t *args,
	void *udata)
{
	struct kp_cam_isp_hw_event_info *event_info;
	struct kp_cam_isp_hw_compdone_event_info *compdone;

	unsigned int i;
	unsigned int num_res;

	if (!armed)
		return;

	event_info =
		(struct kp_cam_isp_hw_event_info *)
		args->arg1;

	if (!event_info)
		return;

	if (!event_info->event_data)
		return;

	compdone =
		(struct kp_cam_isp_hw_compdone_event_info *)
		event_info->event_data;

	num_res = compdone->num_res;

	if (num_res > MAX_RES)
		num_res = MAX_RES;

	done_count++;

	for (i = 0; i < num_res; i++) {

		if (compdone->res_id[i] != RDI_0)
			continue;

		rdi_done_count++;

		pr_info(
			"cam-raw-dump: RDI0 BUF DONE "
			"hw_idx=%u res=0x%x last_addr=0x%x "
			"saved_req=%llu saved_mem=0x%x fd=%d\n",
			event_info->hw_idx,
			compdone->res_id[i],
			compdone->last_consumed_addr[i],
			last_rdi_request,
			last_rdi_handle,
			last_rdi_fd);
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

	addr_buf_done =
		kallsyms_lookup_name(
			"cam_ife_hw_mgr_handle_hw_buf_done");

	pr_info(
		"cam-raw-dump: prepare=%lx "
		"buf_done=%lx\n",
		addr_prepare,
		addr_buf_done);

	if (!addr_prepare || !addr_buf_done)
		return -1;

	if (hook_wrap2(
		(void *)addr_prepare,
		before_prepare,
		NULL,
		NULL))
		return -1;

	if (hook_wrap2(
		(void *)addr_buf_done,
		before_buf_done,
		NULL,
		NULL)) {
		unhook((void *)addr_prepare);
		return -1;
	}

	pr_info(
		"cam-raw-dump: init ok\n");

	return 0;
}

static long cam_kpm_control0(
	const char *args,
	char __user *out_msg,
	int outlen)
{
	char status[32];

	if (!args)
		return -1;

	if (args[0] == 'c') {

		armed = 1;

		prepare_count = 0;
		done_count = 0;
		rdi_done_count = 0;

		last_rdi_fd = -1;
		last_rdi_handle = 0;
		last_rdi_request = 0;

		pr_info(
			"cam-raw-dump: armed\n");

		compat_copy_to_user(
			out_msg,
			"armed",
			6);

	} else if (args[0] == 's') {

		armed = 0;

		pr_info(
			"cam-raw-dump: STOP "
			"prepare=%u done=%u rdi_done=%u "
			"last_req=%llu last_mem=0x%x fd=%d\n",
			prepare_count,
			done_count,
			rdi_done_count,
			last_rdi_request,
			last_rdi_handle,
			last_rdi_fd);

		status[0] = 's';
		status[1] = '\0';

		compat_copy_to_user(
			out_msg,
			status,
			2);
	}

	return 0;
}

static long cam_kpm_exit(
	void *reserved)
{
	armed = 0;

	if (addr_buf_done)
		unhook((void *)addr_buf_done);

	if (addr_prepare)
		unhook((void *)addr_prepare);

	pr_info(
		"cam-raw-dump: exit\n");

	return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
