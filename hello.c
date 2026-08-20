#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.6.5");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("RDI0 64KB chunk capture probe");

#define CAM_BUF_OUTPUT 2
#define RDI_0 0x3006
#define MAX_RES 32

#define CHUNK_SIZE (64 * 1024)
#define TEST_SIZE  (1 * 1024 * 1024)

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

static unsigned long addr_prepare;
static unsigned long addr_buf_done;

static struct dma_buf *(*p_dma_buf_get)(int);
static void (*p_dma_buf_put)(struct dma_buf *);

static int (*p_dma_buf_begin_cpu_access)(
	struct dma_buf *, int);

static int (*p_dma_buf_end_cpu_access)(
	struct dma_buf *, int);

static void *(*p_dma_buf_vmap)(
	struct dma_buf *);

static void (*p_dma_buf_vunmap)(
	struct dma_buf *,
	void *);

static void *(*p_vmalloc)(unsigned long);
static void (*p_vfree)(const void *);

static void *(*p_filp_open)(
	const char *, int, unsigned int);

static long (*p_kernel_write)(
	void *, const void *, unsigned long, long long *);

static int (*p_filp_close)(
	void *, void *);

static volatile int armed;
static volatile int done_seen;

static struct dma_buf *saved_dmabuf;

static volatile int saved_fd;
static volatile unsigned int saved_handle;
static volatile unsigned long long saved_request;

static volatile unsigned int saved_width;
static volatile unsigned int saved_height;
static volatile unsigned int saved_stride;
static volatile unsigned int saved_slice;
static volatile unsigned int saved_format;

static unsigned char *dyn_buf;
static volatile unsigned long cached_len;

static volatile unsigned int prepare_count;
static volatile unsigned int done_count;
static volatile unsigned int copy_ok;
static volatile unsigned int copy_fail;

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
	unsigned int handle;
	int fd;
	struct dma_buf *dmabuf;

	if (!armed || saved_dmabuf)
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

		handle =
			(unsigned int)
			io_cfg[i].mem_handle[0];

		fd =
			(int)(handle >> 16);

		dmabuf =
			p_dma_buf_get(fd);

		if (!dmabuf) {
			pr_info(
				"cam-raw-dump: PREP dma_buf_get "
				"FAILED fd=%d\n",
				fd);

			return;
		}

		saved_dmabuf = dmabuf;
		saved_fd = fd;
		saved_handle = handle;
		saved_request =
			packet->header.request_id;

		saved_width =
			io_cfg[i].planes[0].width;

		saved_height =
			io_cfg[i].planes[0].height;

		saved_stride =
			io_cfg[i].planes[0].plane_stride;

		saved_slice =
			io_cfg[i].planes[0].slice_height;

		saved_format =
			io_cfg[i].format;

		prepare_count++;

		pr_info(
			"cam-raw-dump: PREP saved "
			"req=%llu mem=0x%x fd=%d "
			"w=%u h=%u stride=%u slice=%u "
			"dmabuf=%p\n",
			saved_request,
			saved_handle,
			saved_fd,
			saved_width,
			saved_height,
			saved_stride,
			saved_slice,
			saved_dmabuf);

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

	if (!armed || done_seen)
		return;

	event_info =
		(struct kp_cam_isp_hw_event_info *)args->arg1;

	if (!event_info ||
	    !event_info->event_data)
		return;

	compdone =
		(struct kp_cam_isp_hw_compdone_event_info *)
		event_info->event_data;

	num_res =
		compdone->num_res;

	if (num_res > MAX_RES)
		num_res = MAX_RES;

	done_count++;

	for (i = 0; i < num_res; i++) {

		if (compdone->res_id[i] != RDI_0)
			continue;

		done_seen = 1;

		pr_info(
			"cam-raw-dump: DONE "
			"req=%llu mem=0x%x fd=%d "
			"w=%u h=%u stride=%u slice=%u\n",
			saved_request,
			saved_handle,
			saved_fd,
			saved_width,
			saved_height,
			saved_stride,
			saved_slice);

		return;
	}
}

static int capture_1mb(void)
{
	void *vaddr;
	unsigned long copied;
	unsigned long remaining;
	unsigned long chunk;
	int rc;

	if (!saved_dmabuf ||
	    !dyn_buf ||
	    !done_seen)
		return -1;

	rc =
		p_dma_buf_begin_cpu_access(
			saved_dmabuf,
			0);

	pr_info(
		"cam-raw-dump: begin_cpu_access rc=%d\n",
		rc);

	if (rc)
		return rc;

	vaddr =
		p_dma_buf_vmap(
			saved_dmabuf);

	pr_info(
		"cam-raw-dump: vmap=%lx\n",
		(unsigned long)vaddr);

	if (!vaddr) {
		p_dma_buf_end_cpu_access(
			saved_dmabuf,
			0);

		return -1;
	}

	copied = 0;
	remaining = TEST_SIZE;

	while (remaining) {

		chunk = remaining;

		if (chunk > CHUNK_SIZE)
			chunk = CHUNK_SIZE;

		memcpy(
			dyn_buf + copied,
			(unsigned char *)vaddr + copied,
			chunk);

		copied += chunk;
		remaining -= chunk;
	}

	p_dma_buf_vunmap(
		saved_dmabuf,
		vaddr);

	rc =
		p_dma_buf_end_cpu_access(
			saved_dmabuf,
			0);

	pr_info(
		"cam-raw-dump: chunk copy done "
		"bytes=%lu chunks=%lu "
		"end_cpu_access rc=%d\n",
		copied,
		TEST_SIZE / CHUNK_SIZE,
		rc);

	if (rc)
		return rc;

	cached_len = copied;
	copy_ok++;

	return 0;
}

static int write_cached_frame(void)
{
	void *file;
	long long pos = 0;
	long written;

	if (!dyn_buf ||
	    !cached_len)
		return -1;

	file =
		p_filp_open(
			"/data/local/tmp/rdi0_1mb.raw",
			1 | 256 | 512,
			0644);

	if (is_err_ptr(file))
		return -1;

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
		"cam-raw-dump: written=%ld expected=%lu\n",
		written,
		cached_len);

	return
		(written == (long)cached_len)
		? 0
		: -1;
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

	p_vmalloc =
		(void *)kallsyms_lookup_name(
			"vmalloc");

	p_vfree =
		(void *)kallsyms_lookup_name(
			"vfree");

	p_filp_open =
		(void *)kallsyms_lookup_name(
			"filp_open");

	p_kernel_write =
		(void *)kallsyms_lookup_name(
			"kernel_write");

	p_filp_close =
		(void *)kallsyms_lookup_name(
			"filp_close");

	if (!addr_prepare ||
	    !addr_buf_done ||
	    !p_dma_buf_get ||
	    !p_dma_buf_put ||
	    !p_dma_buf_begin_cpu_access ||
	    !p_dma_buf_end_cpu_access ||
	    !p_dma_buf_vmap ||
	    !p_dma_buf_vunmap ||
	    !p_vmalloc ||
	    !p_vfree ||
	    !p_filp_open ||
	    !p_kernel_write ||
	    !p_filp_close)
		return -1;

	dyn_buf =
		p_vmalloc(TEST_SIZE);

	pr_info(
		"cam-raw-dump: dyn_buf=%p size=%d\n",
		dyn_buf,
		TEST_SIZE);

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

		unhook(
			(void *)addr_prepare);

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
	int rc;

	if (!args)
		return -1;

	if (args[0] == 'c') {

		if (saved_dmabuf) {
			p_dma_buf_put(
				saved_dmabuf);

			saved_dmabuf = NULL;
		}

		armed = 1;
		done_seen = 0;
		cached_len = 0;

		saved_fd = -1;
		saved_handle = 0;
		saved_request = 0;

		prepare_count = 0;
		done_count = 0;
		copy_ok = 0;
		copy_fail = 0;

		pr_info(
			"cam-raw-dump: armed\n");

		compat_copy_to_user(
			out_msg,
			"armed",
			6);

	} else if (args[0] == 'g') {

		if (!saved_dmabuf) {
			pr_info(
				"cam-raw-dump: "
				"no saved dma_buf\n");

			compat_copy_to_user(
				out_msg,
				"no_buf",
				7);

			return 0;
		}

		if (!done_seen) {
			pr_info(
				"cam-raw-dump: "
				"RDI0 DONE not seen\n");

			compat_copy_to_user(
				out_msg,
				"no_done",
				8);

			return 0;
		}

		pr_info(
			"cam-raw-dump: "
			"1MB chunk capture begin\n");

		rc =
			capture_1mb();

		if (!rc) {
			compat_copy_to_user(
				out_msg,
				"capture_ok",
				11);
		} else {
			copy_fail++;

			compat_copy_to_user(
				out_msg,
				"capture_fail",
				13);
		}

	} else if (args[0] == 'w') {

		if (!cached_len) {
			pr_info(
				"cam-raw-dump: "
				"no captured data\n");

			compat_copy_to_user(
				out_msg,
				"no_data",
				8);

			return 0;
		}

		rc =
			write_cached_frame();

		if (!rc) {
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

		armed = 0;

		pr_info(
			"cam-raw-dump: STOP "
			"prepare=%u done=%u "
			"copy_ok=%u copy_fail=%u "
			"cached=%lu dmabuf=%p\n",
			prepare_count,
			done_count,
			copy_ok,
			copy_fail,
			cached_len,
			saved_dmabuf);

		if (saved_dmabuf) {
			p_dma_buf_put(
				saved_dmabuf);

			saved_dmabuf = NULL;
		}

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
	armed = 0;

	if (addr_buf_done)
		unhook(
			(void *)addr_buf_done);

	if (addr_prepare)
		unhook(
			(void *)addr_prepare);

	if (saved_dmabuf &&
	    p_dma_buf_put)
		p_dma_buf_put(
			saved_dmabuf);

	if (dyn_buf &&
	    p_vfree)
		p_vfree(
			dyn_buf);

	saved_dmabuf = NULL;
	dyn_buf = NULL;

	pr_info(
		"cam-raw-dump: exit\n");

	return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
