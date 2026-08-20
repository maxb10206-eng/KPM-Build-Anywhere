#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.6.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("RDI0 capture after BUF DONE from control context");

#define O_WRONLY 00000001
#define O_CREAT  00000100
#define O_TRUNC  00001000

#define CAM_BUF_OUTPUT 2
#define RDI_0 0x3006

#define DYNAMIC_BUF_SIZE (32 * 1024 * 1024)
#define MAX_RES 32

struct dma_buf;

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

struct kp_cam_isp_hw_compdone_event_info {
	unsigned int num_res;
	unsigned int res_id[MAX_RES];
	unsigned int last_consumed_addr[MAX_RES];
};

static void *(*p_filp_open)(
	const char *, int, unsigned int);

static long (*p_kernel_write)(
	void *, const void *, unsigned long, long long *);

static int (*p_filp_close)(
	void *, void *);

static void *(*p_vmalloc)(
	unsigned long);

static void (*p_vfree)(
	const void *);

static struct dma_buf *(*p_dma_buf_get)(int);
static void (*p_dma_buf_put)(struct dma_buf *);

static int (*p_dma_buf_begin_cpu_access)(
	struct dma_buf *, int);

static int (*p_dma_buf_end_cpu_access)(
	struct dma_buf *, int);

static void *(*p_dma_buf_vmap)(
	struct dma_buf *);

static void (*p_dma_buf_vunmap)(
	struct dma_buf *, void *);

static unsigned long addr_prepare;
static unsigned long addr_buf_done;

static unsigned char *dyn_buf;

static volatile char capture_status;
/*
 * 0 = idle
 * 1 = armed
 * 2 = RDI0 BUF DONE captured, waiting for 'g'
 * 3 = memory captured, waiting for 'w'
 * 4 = written
 */

static volatile unsigned int cnt_prepare;
static volatile unsigned int cnt_done;
static volatile unsigned int cnt_get;
static volatile unsigned int cnt_copy_ok;
static volatile unsigned int cnt_copy_fail;

static volatile int capture_fd = -1;
static volatile unsigned int capture_handle;
static volatile unsigned long long capture_request;

static volatile unsigned int capture_width;
static volatile unsigned int capture_height;
static volatile unsigned int capture_stride;
static volatile unsigned int capture_slice;
static volatile unsigned int capture_format;
static volatile unsigned int capture_offset;

static volatile unsigned long cached_len;
static volatile unsigned long cached_request;

static int is_err_ptr(void *ptr)
{
	return (unsigned long)ptr >= (unsigned long)-4095;
}

static void before_prepare(
	hook_fargs2_t *args,
	void *udata)
{
	struct kp_cam_packet *packet;
	struct kp_cam_buf_io_cfg *io_cfg;
	unsigned int i;

	if (capture_status != 1)
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

	for (i = 0; i < packet->num_io_configs; i++) {
		if (io_cfg[i].direction != CAM_BUF_OUTPUT)
			continue;

		if (io_cfg[i].resource_type != RDI_0)
			continue;

		if (!io_cfg[i].mem_handle[0])
			continue;

		capture_handle =
			(unsigned int)io_cfg[i].mem_handle[0];

		capture_fd =
			(int)(capture_handle >> 16);

		capture_request =
			packet->header.request_id;

		capture_width =
			io_cfg[i].planes[0].width;

		capture_height =
			io_cfg[i].planes[0].height;

		capture_stride =
			io_cfg[i].planes[0].plane_stride;

		capture_slice =
			io_cfg[i].planes[0].slice_height;

		capture_format =
			io_cfg[i].format;

		capture_offset =
			io_cfg[i].offsets[0];

		cnt_prepare++;
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

	if (capture_status != 1)
		return;

	event_info =
		(struct kp_cam_isp_hw_event_info *)args->arg1;

	if (!event_info ||
	    !event_info->event_data)
		return;

	compdone =
		(struct kp_cam_isp_hw_compdone_event_info *)
		event_info->event_data;

	num_res = compdone->num_res;

	if (num_res > MAX_RES)
		num_res = MAX_RES;

	cnt_done++;

	for (i = 0; i < num_res; i++) {
		if (compdone->res_id[i] != RDI_0)
			continue;

		/*
		 * 这里只记录 DONE。
		 * 不做 dma_buf / vmap / memcpy。
		 */
		capture_status = 2;

		pr_info(
			"cam-raw-dump: RDI0 DONE "
			"hw=%u last_addr=0x%x "
			"req=%llu mem=0x%x fd=%d "
			"w=%u h=%u stride=%u slice=%u "
			"offset=%u format=%u\n",
			event_info->hw_idx,
			compdone->last_consumed_addr[i],
			capture_request,
			capture_handle,
			capture_fd,
			capture_width,
			capture_height,
			capture_stride,
			capture_slice,
			capture_offset,
			capture_format);

		return;
	}
}

static int capture_frame_from_control_context(void)
{
	struct dma_buf *dmabuf;
	void *vaddr;

	unsigned long len;
	unsigned long offset;

	int rc;

	if (!dyn_buf)
		return -1;

	if (capture_fd < 0)
		return -1;

	if (!p_dma_buf_get ||
	    !p_dma_buf_put ||
	    !p_dma_buf_begin_cpu_access ||
	    !p_dma_buf_end_cpu_access ||
	    !p_dma_buf_vmap ||
	    !p_dma_buf_vunmap)
		return -1;

	len =
		(unsigned long)capture_stride *
		(unsigned long)(
			capture_slice ?
			capture_slice :
			capture_height);

	offset =
		(unsigned long)capture_offset;

	if (!len ||
	    len > DYNAMIC_BUF_SIZE ||
	    offset > DYNAMIC_BUF_SIZE ||
	    offset + len > DYNAMIC_BUF_SIZE) {

		pr_info(
			"cam-raw-dump: invalid capture "
			"len=%lu offset=%lu\n",
			len,
			offset);

		cnt_copy_fail++;
		return -1;
	}

	pr_info(
		"cam-raw-dump: GET capture "
		"fd=%d req=%llu len=%lu "
		"offset=%lu\n",
		capture_fd,
		capture_request,
		len,
		offset);

	dmabuf =
		p_dma_buf_get(capture_fd);

	if (!dmabuf) {
		pr_info(
			"cam-raw-dump: dma_buf_get "
			"failed fd=%d\n",
			capture_fd);

		cnt_copy_fail++;
		return -1;
	}

	cnt_get++;

	rc =
		p_dma_buf_begin_cpu_access(
			dmabuf,
			0);

	if (rc) {
		pr_info(
			"cam-raw-dump: begin_cpu_access "
			"rc=%d\n",
			rc);

		p_dma_buf_put(dmabuf);
		cnt_copy_fail++;
		return -1;
	}

	vaddr =
		p_dma_buf_vmap(dmabuf);

	if (!vaddr) {
		pr_info(
			"cam-raw-dump: vmap failed\n");

		p_dma_buf_end_cpu_access(
			dmabuf,
			0);

		p_dma_buf_put(dmabuf);
		cnt_copy_fail++;
		return -1;
	}

	memcpy(
		dyn_buf,
		(unsigned char *)vaddr + offset,
		len);

	p_dma_buf_vunmap(
		dmabuf,
		vaddr);

	p_dma_buf_end_cpu_access(
		dmabuf,
		0);

	p_dma_buf_put(dmabuf);

	cached_len = len;
	cached_request = capture_request;

	cnt_copy_ok++;
	capture_status = 3;

	pr_info(
		"cam-raw-dump: CAPTURE OK "
		"req=%lu fd=%d len=%lu "
		"w=%u h=%u stride=%u "
		"slice=%u offset=%u format=%u\n",
		cached_request,
		capture_fd,
		cached_len,
		capture_width,
		capture_height,
		capture_stride,
		capture_slice,
		capture_offset,
		capture_format);

	return 0;
}

static int write_cached_frame_to_disk(void)
{
	void *file;
	long long pos = 0;
	long written;

	if (!dyn_buf || !cached_len)
		return -1;

	file =
		p_filp_open(
			"/data/local/tmp/rdi0.raw",
			O_CREAT | O_WRONLY | O_TRUNC,
			0644);

	if (is_err_ptr(file)) {
		pr_err(
			"cam-raw-dump: open failed\n");
		return -1;
	}

	written =
		p_kernel_write(
			file,
			dyn_buf,
			cached_len,
			&pos);

	p_filp_close(
		file,
		NULL);

	pr_info(
		"cam-raw-dump: written=%ld "
		"expected=%lu\n",
		written,
		cached_len);

	if (written != (long)cached_len)
		return -1;

	capture_status = 4;
	return 0;
}

static long cam_kpm_init(
	const char *args,
	const char *event,
	void *reserved)
{
	p_filp_open =
		(void *)kallsyms_lookup_name("filp_open");

	p_kernel_write =
		(void *)kallsyms_lookup_name("kernel_write");

	p_filp_close =
		(void *)kallsyms_lookup_name("filp_close");

	p_vmalloc =
		(void *)kallsyms_lookup_name("vmalloc");

	p_vfree =
		(void *)kallsyms_lookup_name("vfree");

	p_dma_buf_get =
		(void *)kallsyms_lookup_name("dma_buf_get");

	p_dma_buf_put =
		(void *)kallsyms_lookup_name("dma_buf_put");

	p_dma_buf_begin_cpu_access =
		(void *)kallsyms_lookup_name(
			"dma_buf_begin_cpu_access");

	p_dma_buf_end_cpu_access =
		(void *)kallsyms_lookup_name(
			"dma_buf_end_cpu_access");

	p_dma_buf_vmap =
		(void *)kallsyms_lookup_name(
			"dma_buf_vmap");

	p_dma_buf_vunmap =
		(void *)kallsyms_lookup_name(
			"dma_buf_vunmap");

	addr_prepare =
		kallsyms_lookup_name(
			"cam_ife_mgr_prepare_hw_update");

	addr_buf_done =
		kallsyms_lookup_name(
			"cam_ife_hw_mgr_handle_hw_buf_done");

	if (!p_filp_open ||
	    !p_kernel_write ||
	    !p_filp_close ||
	    !p_vmalloc ||
	    !p_vfree ||
	    !p_dma_buf_get ||
	    !p_dma_buf_put ||
	    !p_dma_buf_begin_cpu_access ||
	    !p_dma_buf_end_cpu_access ||
	    !p_dma_buf_vmap ||
	    !p_dma_buf_vunmap ||
	    !addr_prepare ||
	    !addr_buf_done)
		return -1;

	dyn_buf =
		p_vmalloc(
			DYNAMIC_BUF_SIZE);

	pr_info(
		"cam-raw-dump: dyn_buf=%p size=%d\n",
		dyn_buf,
		DYNAMIC_BUF_SIZE);

	if (!dyn_buf)
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
	if (!args)
		return -1;

	if (args[0] == 'c') {
		capture_status = 1;

		cached_len = 0;

		capture_fd = -1;
		capture_handle = 0;
		capture_request = 0;

		cnt_prepare = 0;
		cnt_done = 0;
		cnt_get = 0;
		cnt_copy_ok = 0;
		cnt_copy_fail = 0;

		pr_info(
			"cam-raw-dump: armed\n");

		compat_copy_to_user(
			out_msg,
			"armed",
			6);

	} else if (args[0] == 'g') {
		if (capture_status != 2) {
			pr_info(
				"cam-raw-dump: "
				"no RDI0 DONE frame\n");

			compat_copy_to_user(
				out_msg,
				"no_done",
				8);

			return 0;
		}

		if (capture_frame_from_control_context() == 0) {
			compat_copy_to_user(
				out_msg,
				"capture_ok",
				11);
		} else {
			compat_copy_to_user(
				out_msg,
				"capture_fail",
				13);
		}

	} else if (args[0] == 'w') {
		if (capture_status != 3 ||
		    !cached_len) {

			pr_info(
				"cam-raw-dump: "
				"no captured frame\n");

			compat_copy_to_user(
				out_msg,
				"no_frame",
				9);

			return 0;
		}

		if (write_cached_frame_to_disk() == 0) {
			compat_copy_to_user(
				out_msg,
				"write_ok",
				9);
		} else {
			compat_copy_to_user(
				out_msg,
				"write_fail",
				11);
		}

	} else if (args[0] == 's') {
		capture_status = 0;

		pr_info(
			"cam-raw-dump: STOP "
			"status=%d prepare=%u done=%u "
			"get=%u copy_ok=%u copy_fail=%u "
			"len=%lu req=%lu fd=%d\n",
			capture_status,
			cnt_prepare,
			cnt_done,
			cnt_get,
			cnt_copy_ok,
			cnt_copy_fail,
			cached_len,
			cached_request,
			capture_fd);

		compat_copy_to_user(
			out_msg,
			"stopped",
			8);
	}

	return 0;
}

static long cam_kpm_exit(
	void *reserved)
{
	capture_status = 0;

	if (addr_buf_done)
		unhook(
			(void *)addr_buf_done);

	if (addr_prepare)
		unhook(
			(void *)addr_prepare);

	if (dyn_buf && p_vfree)
		p_vfree(dyn_buf);

	dyn_buf = NULL;

	pr_info(
		"cam-raw-dump: exit\n");

	return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
