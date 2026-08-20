#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/dma-buf.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.3.3");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("RDI0 first-frame RAW dump");

#define CAM_BUF_OUTPUT 2
#define RDI_0 0x3006

#define MAX_CAPTURE_SIZE (64UL * 1024 * 1024)

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
static unsigned long addr_begin_cpu;
static unsigned long addr_end_cpu;
static unsigned long addr_vmap;
static unsigned long addr_vunmap;
static unsigned long addr_filp_open;
static unsigned long addr_filp_close;
static unsigned long addr_kernel_write;

static struct dma_buf *(*kp_dma_buf_get)(int);
static void (*kp_dma_buf_put)(struct dma_buf *);

static int (*kp_begin_cpu)(struct dma_buf *, int);
static int (*kp_end_cpu)(struct dma_buf *, int);

static void *(*kp_vmap)(struct dma_buf *);
static void (*kp_vunmap)(struct dma_buf *, void *);

static struct file *(*kp_filp_open)(
	const char *, int, umode_t);

static int (*kp_filp_close)(
	struct file *, fl_owner_t);

static ssize_t (*kp_kernel_write)(
	struct file *, const void *, size_t, loff_t *);

static volatile int armed;
static volatile int captured;

static void *capture_buf;
static size_t capture_len;
static struct work_struct capture_work;

static void write_capture(struct work_struct *work)
{
	struct file *file;
	loff_t pos = 0;
	ssize_t rc;

	if (!capture_buf || !capture_len)
		return;

	if (!kp_filp_open || !kp_kernel_write || !kp_filp_close)
		return;

	file = kp_filp_open(
		"/data/local/tmp/rdi0.raw",
		O_WRONLY | O_CREAT | O_TRUNC,
		0600);

	if (IS_ERR(file)) {
		pr_info(
			"cam-raw-dump: filp_open failed\n");
		return;
	}

	rc = kp_kernel_write(
		file,
		capture_buf,
		capture_len,
		&pos);

	pr_info(
		"cam-raw-dump: write rc=%ld len=%zu\n",
		(long)rc,
		capture_len);

	kp_filp_close(file, NULL);
}

static void before_prepare(
	hook_fargs2_t *args,
	void *udata)
{
	struct kp_cam_packet *packet;
	struct kp_cam_buf_io_cfg *io_cfg;

	struct dma_buf *buf;
	void *vaddr;

	unsigned int i;
	unsigned int handle;
	unsigned int fd;

	size_t len;
	int rc;

	if (!armed || captured)
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

		fd = handle >> 16;

		pr_info(
			"cam-raw-dump: capture req=%llu "
			"mem=0x%x fd=%u\n",
			packet->header.request_id,
			handle,
			fd);

		buf = kp_dma_buf_get(fd);

		if (!buf) {
			pr_info(
				"cam-raw-dump: dma_buf_get failed\n");
			return;
		}

		rc = kp_begin_cpu(buf, 0);

		if (rc) {
			pr_info(
				"cam-raw-dump: begin_cpu rc=%d\n",
				rc);

			kp_dma_buf_put(buf);
			return;
		}

		len = buf->size;

		pr_info(
			"cam-raw-dump: buffer size=%zu\n",
			len);

		if (!len || len > MAX_CAPTURE_SIZE) {
			pr_info(
				"cam-raw-dump: invalid size=%zu\n",
				len);

			kp_end_cpu(buf, 0);
			kp_dma_buf_put(buf);
			return;
		}

		vaddr = kp_vmap(buf);

		if (!vaddr) {
			pr_info(
				"cam-raw-dump: vmap failed\n");

			kp_end_cpu(buf, 0);
			kp_dma_buf_put(buf);
			return;
		}

		capture_buf = kmalloc(
			len,
			GFP_KERNEL);

		if (!capture_buf) {
			pr_info(
				"cam-raw-dump: kmalloc failed "
				"size=%zu\n",
				len);

			kp_vunmap(buf, vaddr);
			kp_end_cpu(buf, 0);
			kp_dma_buf_put(buf);
			return;
		}

		memcpy(
			capture_buf,
			vaddr,
			len);

		capture_len = len;
		captured = 1;

		pr_info(
			"cam-raw-dump: captured %zu bytes\n",
			len);

		kp_vunmap(buf, vaddr);
		kp_end_cpu(buf, 0);
		kp_dma_buf_put(buf);

		schedule_work(&capture_work);

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

	addr_dma_buf_get =
		kallsyms_lookup_name("dma_buf_get");

	addr_dma_buf_put =
		kallsyms_lookup_name("dma_buf_put");

	addr_begin_cpu =
		kallsyms_lookup_name(
			"dma_buf_begin_cpu_access");

	addr_end_cpu =
		kallsyms_lookup_name(
			"dma_buf_end_cpu_access");

	addr_vmap =
		kallsyms_lookup_name(
			"dma_buf_vmap");

	addr_vunmap =
		kallsyms_lookup_name(
			"dma_buf_vunmap");

	addr_filp_open =
		kallsyms_lookup_name(
			"filp_open");

	addr_filp_close =
		kallsyms_lookup_name(
			"filp_close");

	addr_kernel_write =
		kallsyms_lookup_name(
			"kernel_write");

	pr_info(
		"cam-raw-dump: prepare=%lx get=%lx "
		"begin=%lx vmap=%lx write=%lx\n",
		addr_prepare,
		addr_dma_buf_get,
		addr_begin_cpu,
		addr_vmap,
		addr_kernel_write);

	if (!addr_prepare ||
	    !addr_dma_buf_get ||
	    !addr_dma_buf_put ||
	    !addr_begin_cpu ||
	    !addr_end_cpu ||
	    !addr_vmap ||
	    !addr_vunmap ||
	    !addr_filp_open ||
	    !addr_filp_close ||
	    !addr_kernel_write)
		return -1;

	kp_dma_buf_get =
		(struct dma_buf *(*)(int))
		(void *)addr_dma_buf_get;

	kp_dma_buf_put =
		(void (*)(struct dma_buf *))
		(void *)addr_dma_buf_put;

	kp_begin_cpu =
		(int (*)(struct dma_buf *, int))
		(void *)addr_begin_cpu;

	kp_end_cpu =
		(int (*)(struct dma_buf *, int))
		(void *)addr_end_cpu;

	kp_vmap =
		(void *(*)(struct dma_buf *))
		(void *)addr_vmap;

	kp_vunmap =
		(void (*)(struct dma_buf *, void *))
		(void *)addr_vunmap;

	kp_filp_open =
		(struct file *(*)(const char *, int, umode_t))
		(void *)addr_filp_open;

	kp_filp_close =
		(int (*)(struct file *, fl_owner_t))
		(void *)addr_filp_close;

	kp_kernel_write =
		(ssize_t (*)(struct file *,
			     const void *,
			     size_t,
			     loff_t *))
		(void *)addr_kernel_write;

	INIT_WORK(
		&capture_work,
		write_capture);

	if (hook_wrap2(
		(void *)addr_prepare,
		before_prepare,
		NULL,
		NULL))
		return -1;

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

		armed = 1;
		captured = 0;

		pr_info(
			"cam-raw-dump: armed\n");

		compat_copy_to_user(
			out_msg,
			"armed",
			6);

	} else if (args[0] == 's') {

		armed = 0;

		pr_info(
			"cam-raw-dump: stopped "
			"captured=%d len=%zu\n",
			captured,
			capture_len);

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
	if (addr_prepare)
		unhook(
			(void *)addr_prepare);

	cancel_work_sync(
		&capture_work);

	if (capture_buf) {
		kfree(capture_buf);
		capture_buf = NULL;
		capture_len = 0;
	}

	pr_info(
		"cam-raw-dump: exit\n");

	return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
