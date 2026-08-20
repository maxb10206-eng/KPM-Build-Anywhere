#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.6.5");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("RDI0 chunked RAW read test");

#define O_WRONLY 00000001
#define O_CREAT  00000100
#define O_TRUNC  00001000

#define CAM_BUF_OUTPUT 2
#define RDI_0 0x3006
#define MAX_RES 32

/*
 * 单次 memcpy 只做 64 KB。
 * 默认总读取量为 1 MB。
 */
#define CHUNK_SIZE      (64UL * 1024)
#define DEFAULT_TESTLEN (1UL * 1024 * 1024)

/*
 * 你的实际 RDI0 buffer 大约 24,064,000 bytes。
 * 这里预留 32 MB。
 */
#define CAPTURE_BUF_SIZE (32UL * 1024 * 1024)

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
static volatile unsigned int saved_offset;

static volatile unsigned int prepare_count;
static volatile unsigned int done_count;

static volatile int last_test_result;

/*
 * 32 MB 目标缓冲区。
 */
static unsigned char *capture_buf;

/*
 * 实际已经读取的字节数。
 */
static volatile unsigned long captured_len;

/*
 * 本次测试目标。
 */
static volatile unsigned long test_len;

static int is_err_ptr(void *ptr)
{
	return (unsigned long)ptr >=
		(unsigned long)-4095;
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

	for (i = 0;
	     i < packet->num_io_configs;
	     i++) {

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

		/*
		 * 这里只拿引用，不在这里做 CPU 访问。
		 */
		dmabuf =
			p_dma_buf_get(fd);

		if (!dmabuf) {
			pr_info(
				"cam-raw-dump: PREP "
				"dma_buf_get failed fd=%d\n",
				fd);

			last_test_result = -1;
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

		saved_offset =
			io_cfg[i].offsets[0];

		prepare_count++;

		pr_info(
			"cam-raw-dump: PREP saved "
			"req=%llu mem=0x%x fd=%d "
			"w=%u h=%u stride=%u "
			"slice=%u offset=%u\n",
			saved_request,
			saved_handle,
			saved_fd,
			saved_width,
			saved_height,
			saved_stride,
			saved_slice,
			saved_offset);

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

	for (i = 0;
	     i < num_res;
	     i++) {

		if (compdone->res_id[i] != RDI_0)
			continue;

		done_seen = 1;

		/*
		 * 完成点只负责锁定 buffer。
		 */
		armed = 0;

		pr_info(
			"cam-raw-dump: RDI0 DONE "
			"req=%llu mem=0x%x fd=%d "
			"last=0x%x\n",
			saved_request,
			saved_handle,
			saved_fd,
			compdone->last_consumed_addr[i]);

		return;
	}
}

static int capture_chunked(void)
{
	void *vaddr;
	unsigned long remaining;
	unsigned long copy_len;
	unsigned long src_off;
	unsigned long dst_off;

	unsigned char *src;
	unsigned char *dst;

	int rc;

	if (!saved_dmabuf)
		return -1;

	if (!done_seen)
		return -2;

	if (!capture_buf)
		return -3;

	if (!test_len)
		return -4;

	if (test_len > CAPTURE_BUF_SIZE)
		return -5;

	pr_info(
		"cam-raw-dump: chunk capture "
		"begin target=%lu chunk=%lu\n",
		test_len,
		CHUNK_SIZE);

	rc =
		p_dma_buf_begin_cpu_access(
			saved_dmabuf,
			0);

	if (rc) {
		pr_info(
			"cam-raw-dump: begin_cpu rc=%d\n",
			rc);
		return -6;
	}

	vaddr =
		p_dma_buf_vmap(
			saved_dmabuf);

	if (!vaddr) {
		pr_info(
			"cam-raw-dump: vmap failed\n");

		p_dma_buf_end_cpu_access(
			saved_dmabuf,
			0);

		return -7;
	}

	src =
		(unsigned char *)vaddr;

	dst =
		capture_buf;

	/*
	 * 从指定 offset 开始读。
	 */
	src_off = saved_offset;
	dst_off = 0;

	remaining = test_len;

	while (remaining > 0) {

		copy_len =
			remaining > CHUNK_SIZE
			? CHUNK_SIZE
			: remaining;

		memcpy(
			dst + dst_off,
			src + src_off,
			copy_len);

		dst_off += copy_len;
		src_off += copy_len;
		remaining -= copy_len;

		/*
		 * 每复制 1 MB 打一条日志，
		 * 方便判断到底在哪个阶段出问题。
		 */
		if ((dst_off & ((1UL << 20) - 1)) == 0) {
			pr_info(
				"cam-raw-dump: copied %lu/%lu\n",
				dst_off,
				test_len);
		}
	}

	p_dma_buf_vunmap(
		saved_dmabuf,
		vaddr);

	rc =
		p_dma_buf_end_cpu_access(
			saved_dmabuf,
			0);

	if (rc) {
		pr_info(
			"cam-raw-dump: end_cpu rc=%d\n",
			rc);

		last_test_result = rc;
		return -8;
	}

	captured_len = dst_off;
	last_test_result = 0;

	pr_info(
		"cam-raw-dump: CHUNK CAPTURE OK "
		"len=%lu req=%llu w=%u h=%u "
		"stride=%u offset=%u format=%u\n",
		captured_len,
		saved_request,
		saved_width,
		saved_height,
		saved_stride,
		saved_offset,
		saved_format);

	return 0;
}

static int write_capture(void)
{
	void *file;
	long long pos = 0;
	long written;

	if (!capture_buf || !captured_len)
		return -1;

	file =
		p_filp_open(
			"/data/local/tmp/rdi0.raw",
			O_CREAT | O_WRONLY | O_TRUNC,
			0644);

	if (is_err_ptr(file))
		return -2;

	written =
		p_kernel_write(
			file,
			capture_buf,
			captured_len,
			&pos);

	p_filp_close(
		file,
		NULL);

	pr_info(
		"cam-raw-dump: WRITE "
		"written=%ld expected=%lu\n",
		written,
		captured_len);

	return written == (long)captured_len
		? 0
		: -3;
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

	capture_buf =
		(unsigned char *)p_vmalloc(
			CAPTURE_BUF_SIZE);

	pr_info(
		"cam-raw-dump: capture_buf=%p "
		"size=%lu\n",
		capture_buf,
		CAPTURE_BUF_SIZE);

	if (!capture_buf)
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

		saved_fd = -1;
		saved_handle = 0;
		saved_request = 0;

		captured_len = 0;
		test_len = DEFAULT_TESTLEN;

		prepare_count = 0;
		done_count = 0;

		last_test_result = 0;

		pr_info(
			"cam-raw-dump: armed "
			"test_len=%lu\n",
			test_len);

		compat_copy_to_user(
			out_msg,
			"armed",
			6);

	} else if (args[0] == 'g') {

		if (!saved_dmabuf ||
		    !done_seen) {

			pr_info(
				"cam-raw-dump: "
				"no DONE frame\n");

			compat_copy_to_user(
				out_msg,
				"no_done",
				8);

			return 0;
		}

		rc =
			capture_chunked();

		if (rc == 0) {

			compat_copy_to_user(
				out_msg,
				"capture_ok",
				11);

		} else {

			pr_info(
				"cam-raw-dump: "
				"chunk capture rc=%d\n",
				rc);

			compat_copy_to_user(
				out_msg,
				"capture_fail",
				13);
		}

	} else if (args[0] == 'w') {

		rc =
			write_capture();

		if (rc == 0) {

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
			"captured=%lu result=%d "
			"req=%llu fd=%d\n",
			prepare_count,
			done_count,
			captured_len,
			last_test_result,
			saved_request,
			saved_fd);

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

	saved_dmabuf = NULL;

	if (capture_buf &&
	    p_vfree)
		p_vfree(
			capture_buf);

	capture_buf = NULL;

	pr_info(
		"cam-raw-dump: exit\n");

	return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
