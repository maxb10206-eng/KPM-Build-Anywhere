#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.4.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Camera RDI0 raw capture with safe deferred disk write");

#define O_WRONLY 00000001
#define O_CREAT  00000100
#define O_TRUNC  00001000

#define CAM_BUF_OUTPUT 2
#define RDI_0 0x3006

#define DYNAMIC_BUF_SIZE (32 * 1024 * 1024)

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

static unsigned char *dyn_buf;

static volatile char capture_status;

static volatile unsigned int cnt_hook;
static volatile unsigned int cnt_rdi;
static volatile unsigned int cnt_copy_ok;
static volatile unsigned int cnt_copy_fail;

static volatile unsigned long cached_len;
static volatile unsigned long cached_request;
static volatile unsigned int cached_width;
static volatile unsigned int cached_height;
static volatile unsigned int cached_stride;
static volatile unsigned int cached_format;

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

	struct dma_buf *dmabuf;
	void *vaddr;

	unsigned int i;
	unsigned int handle;
	unsigned int fd;

	unsigned long width;
	unsigned long height;
	unsigned long stride;
	unsigned long slice_height;
	unsigned long len;
	unsigned long offset;

	int rc;

	cnt_hook++;

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

	for (i = 0;
	     i < packet->num_io_configs;
	     i++) {

		if (io_cfg[i].direction != CAM_BUF_OUTPUT)
			continue;

		if (io_cfg[i].resource_type != RDI_0)
			continue;

		if (!io_cfg[i].mem_handle[0])
			continue;

		cnt_rdi++;

		width =
			io_cfg[i].planes[0].width;

		height =
			io_cfg[i].planes[0].height;

		stride =
			io_cfg[i].planes[0].plane_stride;

		slice_height =
			io_cfg[i].planes[0].slice_height;

		if (!slice_height)
			slice_height = height;

		len = stride * slice_height;
		offset = io_cfg[i].offsets[0];

		if (!len ||
		    len > DYNAMIC_BUF_SIZE) {

			pr_info(
				"cam-raw-dump: invalid RDI0 "
				"len=%lu width=%lu height=%lu "
				"stride=%lu slice=%lu\n",
				len,
				width,
				height,
				stride,
				slice_height);

			cnt_copy_fail++;
			return;
		}

		handle =
			(unsigned int)
			io_cfg[i].mem_handle[0];

		fd = handle >> 16;

		pr_info(
			"cam-raw-dump: RDI0 req=%llu "
			"mem=0x%x fd=%u width=%lu "
			"height=%lu stride=%lu len=%lu "
			"offset=%lu format=%u\n",
			packet->header.request_id,
			handle,
			fd,
			width,
			height,
			stride,
			len,
			offset,
			io_cfg[i].format);

		dmabuf =
			p_dma_buf_get((int)fd);

		if (!dmabuf) {
			pr_info(
				"cam-raw-dump: dma_buf_get failed "
				"fd=%u\n",
				fd);

			cnt_copy_fail++;
			return;
		}

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
			return;
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
			return;
		}

		if (offset + len > DYNAMIC_BUF_SIZE) {
			pr_info(
				"cam-raw-dump: capture size "
				"exceeds local buffer\n");

			p_dma_buf_vunmap(
				dmabuf,
				vaddr);

			p_dma_buf_end_cpu_access(
				dmabuf,
				0);

			p_dma_buf_put(dmabuf);

			cnt_copy_fail++;
			return;
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
		cached_request =
			(unsigned long)
			packet->header.request_id;

		cached_width =
			(unsigned int)width;

		cached_height =
			(unsigned int)height;

		cached_stride =
			(unsigned int)stride;

		cached_format =
			io_cfg[i].format;

		cnt_copy_ok++;
		capture_status = 2;

		pr_info(
			"cam-raw-dump: CAPTURE OK "
			"req=%lu len=%lu width=%u "
			"height=%u stride=%u format=%u\n",
			cached_request,
			cached_len,
			cached_width,
			cached_height,
			cached_stride,
			cached_format);

		return;
	}
}

static int write_cached_frame_to_disk(void)
{
	void *file;
	long long pos = 0;
	long written;

	if (!cached_len || !dyn_buf)
		return -1;

	file = p_filp_open(
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
		"expected=%lu req=%lu\n",
		written,
		cached_len,
		cached_request);

	if (written != (long)cached_len)
		return -1;

	return 0;
}

static long cam_kpm_init(
	const char *args,
	const char *event,
	void *reserved)
{
	p_filp_open =
		(void *)kallsyms_lookup_name(
			"filp_open");

	p_kernel_write =
		(void *)kallsyms_lookup_name(
			"kernel_write");

	p_filp_close =
		(void *)kallsyms_lookup_name(
			"filp_close");

	p_vmalloc =
		(void *)kallsyms_lookup_name(
			"vmalloc");

	p_vfree =
		(void *)kallsyms_lookup_name(
			"vfree");

	p_dma_buf_get =
		(void *)kallsyms_lookup_name(
			"dma_buf_get");

	p_dma_buf_put =
		(void *)kallsyms_lookup_name(
			"dma_buf_put");

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
	    !addr_prepare) {

		pr_err(
			"cam-raw-dump: symbol lookup failed\n");

		return -1;
	}

	dyn_buf =
		p_vmalloc(
			DYNAMIC_BUF_SIZE);

	pr_info(
		"cam-raw-dump: dyn_buf=%p size=%d\n",
		dyn_buf,
		DYNAMIC_BUF_SIZE);

	if (!dyn_buf) {
		pr_err(
			"cam-raw-dump: vmalloc failed\n");

		return -1;
	}

	if (hook_wrap2(
		(void *)addr_prepare,
		before_prepare,
		NULL,
		NULL)) {

		pr_err(
			"cam-raw-dump: hook prepare failed\n");

		p_vfree(dyn_buf);
		dyn_buf = NULL;

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
	char status[16];

	if (!args)
		return -1;

	if (args[0] == 'c') {

		capture_status = 1;

		cached_len = 0;

		pr_info(
			"cam-raw-dump: armed\n");

		compat_copy_to_user(
			out_msg,
			"armed",
			6);

	} else if (args[0] == 'w') {

		if (capture_status != 2 ||
		    !cached_len) {

			pr_info(
				"cam-raw-dump: no frame\n");

			compat_copy_to_user(
				out_msg,
				"no_frame",
				9);

			return 0;
		}

		if (write_cached_frame_to_disk() == 0) {

			capture_status = 3;

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

		pr_info(
			"cam-raw-dump: status=%d "
			"hook=%u rdi=%u copy_ok=%u "
			"copy_fail=%u cached_len=%lu "
			"req=%lu width=%u height=%u "
			"stride=%u format=%u\n",
			capture_status,
			cnt_hook,
			cnt_rdi,
			cnt_copy_ok,
			cnt_copy_fail,
			cached_len,
			cached_request,
			cached_width,
			cached_height,
			cached_stride,
			cached_format);

		status[0] = 's';
		status[1] = '0' + capture_status;
		status[2] = '\0';

		compat_copy_to_user(
			out_msg,
			status,
			3);
	}

	return 0;
}

static long cam_kpm_exit(
	void *reserved)
{
	if (addr_prepare)
		unhook(
			(void *)addr_prepare);

	if (dyn_buf &&
	    p_vfree)
		p_vfree(dyn_buf);

	dyn_buf = NULL;

	pr_info(
		"cam-raw-dump: exit\n");

	return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
