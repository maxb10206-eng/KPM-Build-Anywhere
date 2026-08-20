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
KPM_DESCRIPTION("RDI0 1MB memcpy probe");

#define CAM_BUF_OUTPUT 2
#define RDI_0 0x3006
#define MAX_RES 32

#define TEST_COPY_SIZE (32UL * 1024 * 1024)

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
	struct dma_buf *,
	int);

static int (*p_dma_buf_end_cpu_access)(
	struct dma_buf *,
	int);

static void *(*p_dma_buf_vmap)(
	struct dma_buf *);

static void (*p_dma_buf_vunmap)(
	struct dma_buf *,
	void *);

static void *(*p_vmalloc)(unsigned long);
static void (*p_vfree)(const void *);

static unsigned char *copy_buf;

static volatile int armed;
static volatile int done_seen;

static struct dma_buf *saved_dmabuf;

static volatile int saved_fd;
static volatile unsigned int saved_handle;
static volatile unsigned long long saved_request;

static volatile unsigned int prepare_count;
static volatile unsigned int done_count;

static volatile int test_result;

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

		fd = (int)(handle >> 16);

		dmabuf =
			p_dma_buf_get(fd);

		if (!dmabuf) {
			pr_info(
				"cam-raw-dump: "
				"PREP dma_buf_get FAILED fd=%d\n",
				fd);

			test_result = -1;
			return;
		}

		saved_dmabuf = dmabuf;
		saved_fd = fd;
		saved_handle = handle;
		saved_request = packet->header.request_id;

		prepare_count++;

		pr_info(
			"cam-raw-dump: PREP saved "
			"req=%llu mem=0x%x fd=%d "
			"dmabuf=%p\n",
			saved_request,
			saved_handle,
			saved_fd,
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

	num_res = compdone->num_res;

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
			"dmabuf=%p\n",
			saved_request,
			saved_handle,
			saved_fd,
			saved_dmabuf);

		return;
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
		(void *)kallsyms_lookup_name("dma_buf_vmap");

	p_dma_buf_vunmap =
		(void *)kallsyms_lookup_name("dma_buf_vunmap");

	p_vmalloc =
		(void *)kallsyms_lookup_name("vmalloc");

	p_vfree =
		(void *)kallsyms_lookup_name("vfree");

	if (!addr_prepare ||
	    !addr_buf_done ||
	    !p_dma_buf_get ||
	    !p_dma_buf_put ||
	    !p_dma_buf_begin_cpu_access ||
	    !p_dma_buf_end_cpu_access ||
	    !p_dma_buf_vmap ||
	    !p_dma_buf_vunmap ||
	    !p_vmalloc ||
	    !p_vfree)
		return -1;

	copy_buf =
		p_vmalloc(TEST_COPY_SIZE);

	if (!copy_buf) {
		pr_info(
			"cam-raw-dump: "
			"vmalloc %lu failed\n",
			TEST_COPY_SIZE);
		return -1;
	}

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
		"cam-raw-dump: init ok "
		"copy=%lu bytes\n",
		TEST_COPY_SIZE);

	return 0;
}

static long cam_kpm_control0(
	const char *args,
	char __user *out_msg,
	int outlen)
{
	void *vaddr;
	int rc;

	if (!args)
		return -1;

	if (args[0] == 'c') {

		if (saved_dmabuf) {
			p_dma_buf_put(saved_dmabuf);
			saved_dmabuf = NULL;
		}

		armed = 1;
		done_seen = 0;
		test_result = 0;

		saved_fd = -1;
		saved_handle = 0;
		saved_request = 0;

		prepare_count = 0;
		done_count = 0;

		pr_info(
			"cam-raw-dump: armed\n");

		compat_copy_to_user(
			out_msg,
			"armed",
			6);

	} else if (args[0] == 'g') {

		if (!saved_dmabuf || !done_seen) {
			pr_info(
				"cam-raw-dump: "
				"no DONE frame\n");

			compat_copy_to_user(
				out_msg,
				"no_done",
				8);

			return 0;
		}

		if (!copy_buf) {
			compat_copy_to_user(
				out_msg,
				"no_dst",
				7);

			return 0;
		}

		pr_info(
			"cam-raw-dump: "
			"1MB COPY begin "
			"req=%llu fd=%d dst=%p\n",
			saved_request,
			saved_fd,
			copy_buf);

		rc =
			p_dma_buf_begin_cpu_access(
				saved_dmabuf,
				0);

		pr_info(
			"cam-raw-dump: "
			"begin_cpu rc=%d\n",
			rc);

		if (rc) {
			test_result = rc;

			compat_copy_to_user(
				out_msg,
				"begin_fail",
				11);

			return 0;
		}

		vaddr =
			p_dma_buf_vmap(
				saved_dmabuf);

		pr_info(
			"cam-raw-dump: "
			"vmap=%lx\n",
			(unsigned long)vaddr);

		if (!vaddr) {
			test_result = -1;

			p_dma_buf_end_cpu_access(
				saved_dmabuf,
				0);

			compat_copy_to_user(
				out_msg,
				"vmap_fail",
				10);

			return 0;
		}

		/*
		 * 只复制 1 MiB。
		 */
		memcpy(
			copy_buf,
			vaddr,
			TEST_COPY_SIZE);

		pr_info(
			"cam-raw-dump: "
			"1MB COPY OK\n");

		p_dma_buf_vunmap(
			saved_dmabuf,
			vaddr);

		pr_info(
			"cam-raw-dump: vunmap ok\n");

		rc =
			p_dma_buf_end_cpu_access(
				saved_dmabuf,
				0);

		test_result = rc;

		pr_info(
			"cam-raw-dump: "
			"end_cpu rc=%d\n",
			rc);

		compat_copy_to_user(
			out_msg,
			"copy1m_ok",
			10);

	} else if (args[0] == 's') {

		armed = 0;

		pr_info(
			"cam-raw-dump: STOP "
			"prepare=%u done=%u "
			"result=%d\n",
			prepare_count,
			done_count,
			test_result);

		if (saved_dmabuf) {
			p_dma_buf_put(saved_dmabuf);
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
		p_dma_buf_put(saved_dmabuf);

	if (copy_buf &&
	    p_vfree)
		p_vfree(copy_buf);

	saved_dmabuf = NULL;
	copy_buf = NULL;

	pr_info(
		"cam-raw-dump: exit\n");

	return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
