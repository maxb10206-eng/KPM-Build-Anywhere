#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>


KPM_NAME("cam-raw-dump");
KPM_VERSION("1.3.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("RDI dma_buf CPU mapper");


#define CAM_BUF_OUTPUT 2

#define CAM_PACKET_MAX_PLANES 3

#define CAM_ISP_IFE_OUT_RES_RDI_0 0x3006
#define CAM_ISP_IFE_OUT_RES_RDI_1 0x3007
#define CAM_ISP_IFE_OUT_RES_RDI_2 0x3008
#define CAM_ISP_IFE_OUT_RES_RDI_3 0x3009


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



/*
 * dma buf
 */

struct dma_buf;


static struct dma_buf *(*kp_dma_buf_get)(int fd);

static void (*kp_dma_buf_put)(struct dma_buf *);


static int (*kp_dma_buf_begin_cpu_access)(
	struct dma_buf *,
	int);


static int (*kp_dma_buf_vmap)(
	struct dma_buf *,
	void **);


static void (*kp_dma_buf_vunmap)(
	struct dma_buf *,
	void *);




static unsigned long addr_prepare;



static volatile int armed;

static volatile int dumped;



static unsigned int frame_count;



static void dump_buffer(struct dma_buf *buf)
{

	int rc;

	void *vaddr = NULL;


	if (!buf)
		return;


	if (dumped)
		return;



/*
 * DMA_BIDIRECTIONAL = 0
 */

	rc = kp_dma_buf_begin_cpu_access(
			buf,
			0);


	if (rc)
	{
		pr_info(
		"cam-raw-dump: begin_cpu_access failed %d\n",
		rc);

		return;
	}



	rc = kp_dma_buf_vmap(
			buf,
			&vaddr);



if (rc || !vaddr)
{

	pr_info(
	"cam-raw-dump: vmap failed rc=%d addr=%lx\n",
	rc,
	(unsigned long)vaddr);


return;

}



pr_info(
"cam-raw-dump: CPU MAP SUCCESS addr=%lx size=%llu\n",
(unsigned long)vaddr,
(unsigned long long)buf->size);



/*
 * 下一版这里 memcpy 到文件
 */


dumped=1;


kp_dma_buf_vunmap(
	buf,
	vaddr);



}



static void before_prepare(
	hook_fargs2_t *args,
	void *udata)
{


struct kp_cam_packet *packet;

struct kp_cam_buf_io_cfg *io_cfg;


unsigned int i;



if (!armed || dumped)
	return;



packet =
*(struct kp_cam_packet **)args->arg1;



if (!packet)
	return;



io_cfg =
(struct kp_cam_buf_io_cfg *)
(
(unsigned char *)packet->payload
+
packet->io_configs_offset
);



for(i=0;i<packet->num_io_configs;i++)
{


if(io_cfg[i].direction != CAM_BUF_OUTPUT)
	continue;



if(io_cfg[i].resource_type != CAM_ISP_IFE_OUT_RES_RDI_0)
	continue;



pr_info(
"cam-raw-dump: RDI0 request=%llu\n",
packet->header.request_id);



if(io_cfg[i].mem_handle[0])
{

int fd;

struct dma_buf *buf;



/*
 * handle里面取fd
 */

fd =
io_cfg[i].mem_handle[0] >> 16;



pr_info(
"cam-raw-dump: handle=%x fd=%d\n",
io_cfg[i].mem_handle[0],
fd);



buf =
kp_dma_buf_get(fd);



if(buf)
{

pr_info(
"cam-raw-dump: dma_buf=%lx\n",
(unsigned long)buf);


dump_buffer(buf);


kp_dma_buf_put(buf);

}


}


break;

}



}




static long cam_init(
const char *args,
const char *event,
void *reserved)
{


addr_prepare =
kallsyms_lookup_name(
"cam_ife_mgr_prepare_hw_update");



kp_dma_buf_get =
(void *)kallsyms_lookup_name(
"dma_buf_get");


kp_dma_buf_put =
(void *)kallsyms_lookup_name(
"dma_buf_put");



kp_dma_buf_begin_cpu_access =
(void *)kallsyms_lookup_name(
"dma_buf_begin_cpu_access");


kp_dma_buf_vmap =
(void *)kallsyms_lookup_name(
"dma_buf_vmap");


kp_dma_buf_vunmap =
(void *)kallsyms_lookup_name(
"dma_buf_vunmap");



pr_info(
"cam-raw-dump: prepare=%lx get=%lx vmap=%lx\n",
addr_prepare,
(unsigned long)kp_dma_buf_get,
(unsigned long)kp_dma_buf_vmap);



if(!addr_prepare ||
!kp_dma_buf_get ||
!kp_dma_buf_vmap)
return -1;



if(hook_wrap2(
(void *)addr_prepare,
before_prepare,
NULL,
NULL))
return -1;



pr_info(
"cam-raw-dump: init ok\n");


return 0;

}





static long cam_control(
const char *args,
char __user *out_msg,
int outlen)
{


if(args[0]=='c')
{

armed=1;
dumped=0;

pr_info(
"cam-raw-dump armed\n");


}



else if(args[0]=='s')
{

armed=0;


pr_info(
"cam-raw-dump stop frames=%u\n",
frame_count);


}


return 0;

}




static long cam_exit(void *reserved)
{

if(addr_prepare)
unhook(
(void *)addr_prepare);



pr_info(
"cam-raw-dump exit\n");


return 0;

}




KPM_INIT(cam_init);
KPM_CTL0(cam_control);
KPM_EXIT(cam_exit);
