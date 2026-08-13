#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("cam-raw-dump");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KC");
KPM_DESCRIPTION("Camera RDI raw data extractor via VFE bus hook");

#define O_WRONLY 00000001
#define O_CREAT  00000100
#define O_TRUNC  00001000

#define CHUNK_SIZE (2 * 1024 * 1024)
#define MAX_MAP_ENTRIES 64

static unsigned char chunk_buf[CHUNK_SIZE];

static void *(*p_filp_open)(const char *, int, unsigned short);
static long (*p_kernel_write)(void *, const void *, unsigned long, long long *);
static int (*p_filp_close)(void *, void *);
static int (*p_cam_mem_get_cpu_buf)(int32_t, uintptr_t *, size_t *);

static unsigned long addr_get_io_buf;
static unsigned long addr_vfe_out_done;

struct iova_map_entry {
    uint32_t iova;
    int32_t buf_handle;
};

static struct iova_map_entry iova_map[MAX_MAP_ENTRIES];
static int map_idx;

static volatile char capture_status;

static volatile unsigned int cnt_hookA_before;
static volatile unsigned int cnt_hookA_after;
static volatile unsigned int cnt_hookB_total;
static volatile unsigned int cnt_hookB_wrong_status;
static volatile unsigned int cnt_hookB_no_handle;
static volatile unsigned int cnt_hookB_getcpu_fail;

static volatile int dump_count;


static void record_iova_mapping(uint32_t iova, int32_t handle)
{
    iova_map[map_idx].iova = iova;
    iova_map[map_idx].buf_handle = handle;

    map_idx++;

    if (map_idx >= MAX_MAP_ENTRIES)
        map_idx = 0;
}


static int32_t lookup_buf_handle(uint32_t iova)
{
    int i;

    for (i = 0; i < MAX_MAP_ENTRIES; i++) {
        int idx = (map_idx - 1 - i + MAX_MAP_ENTRIES)
                  % MAX_MAP_ENTRIES;

        if (iova_map[idx].iova == iova)
            return iova_map[idx].buf_handle;
    }

    return 0;
}


static int is_err_ptr(void *ptr)
{
    return (unsigned long)ptr >= (unsigned long)-4095;
}


static void before_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_before++;
    args->local.data0 = args->arg0;
}


static void after_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_after++;
    int32_t handle = (int32_t)args->local.data0;
    dma_addr_t *iova = (dma_addr_t *)args->arg2;

    if (iova && handle) {
        record_iova_mapping((uint32_t)*iova, handle);
    }
}


// 新假设结构体:前面加16字节list_head前缀
#define CAM_NUM_OUT_PER_COMP_IRQ_MAX 6

struct cam_isp_hw_done_event_data_v2 {
    void *list_next;
    void *list_prev;
    uint32_t num_handles;
    uint32_t resource_handle[CAM_NUM_OUT_PER_COMP_IRQ_MAX];
    uint32_t last_consumed_addr[CAM_NUM_OUT_PER_COMP_IRQ_MAX];
    uint64_t timestamp;
};


static void before_vfe_out_done(hook_fargs2_t *args, void *udata)
{
    cnt_hookB_total++;

    if (capture_status != 1) {
        cnt_hookB_wrong_status++;
        return;
    }

    void *evt_ptr = (void *)args->arg1;

    if (!evt_ptr) {
        return;
    }

    // 扩大dump范围到raw[0]~raw[23],覆盖96字节,足够看到真正的last_consumed_addr
    if (dump_count < 3) {
        dump_count++;
        uint32_t *raw = (uint32_t *)evt_ptr;
        pr_info("cam-raw-dump: RAW[0-3]  = %x %x %x %x\n", raw[0], raw[1], raw[2], raw[3]);
        pr_info("cam-raw-dump: RAW[4-7]  = %x %x %x %x\n", raw[4], raw[5], raw[6], raw[7]);
        pr_info("cam-raw-dump: RAW[8-11] = %x %x %x %x\n", raw[8], raw[9], raw[10], raw[11]);
        pr_info("cam-raw-dump: RAW[12-15]= %x %x %x %x\n", raw[12], raw[13], raw[14], raw[15]);
        pr_info("cam-raw-dump: RAW[16-19]= %x %x %x %x\n", raw[16], raw[17], raw[18], raw[19]);
        pr_info("cam-raw-dump: RAW[20-23]= %x %x %x %x\n", raw[20], raw[21], raw[22], raw[23]);
    }

    // 用新假设的结构体去解析,试试看
    struct cam_isp_hw_done_event_data_v2 *evt = (struct cam_isp_hw_done_event_data_v2 *)evt_ptr;

    if (!evt->num_handles) {
        return;
    }

    if (!p_cam_mem_get_cpu_buf)
        return;

    uint32_t iova = evt->last_consumed_addr[0];
    int32_t handle = lookup_buf_handle(iova);

    if (!handle) {
        cnt_hookB_no_handle++;
        return;
    }

    uintptr_t vaddr = 0;
    size_t len = 0;

    if (p_cam_mem_get_cpu_buf(handle, &vaddr, &len)) {
        cnt_hookB_getcpu_fail++;
        return;
    }

    if (!vaddr || !len) {
        cnt_hookB_getcpu_fail++;
        return;
    }


    void *f = p_filp_open(
        "/data/local/tmp/cam_frame.raw",
        O_CREAT | O_WRONLY | O_TRUNC,
        0644
    );

    if (is_err_ptr(f)) {
        pr_err("cam-raw-dump: open failed\n");
        return;
    }


    long long pos = 0;
    size_t remain = len;
    uintptr_t src = vaddr;

    while (remain) {
        size_t n = remain > CHUNK_SIZE ? CHUNK_SIZE : remain;

        memcpy(chunk_buf, (void *)src, n);

        if (p_kernel_write(f, chunk_buf, n, &pos) < 0)
            break;

        src += n;
        remain -= n;
    }


    p_filp_close(f, NULL);

    capture_status = 2;

    pr_info("cam-raw-dump: frame written size=%zu\n", len);
}


static long cam_kpm_init(
    const char *args,
    const char *event,
    void *reserved)
{
    pr_info("cam-raw-dump: symbol lookup\n");

    p_filp_open =
        (void *)kallsyms_lookup_name("filp_open");

    p_kernel_write =
        (void *)kallsyms_lookup_name("kernel_write");

    p_filp_close =
        (void *)kallsyms_lookup_name("filp_close");

    p_cam_mem_get_cpu_buf =
        (void *)kallsyms_lookup_name("cam_mem_get_cpu_buf");


    addr_get_io_buf =
        kallsyms_lookup_name("cam_mem_get_io_buf");

    addr_vfe_out_done =
        kallsyms_lookup_name(
        "cam_vfe_bus_ver3_handle_vfe_out_done_bottom_half");


    if (!p_filp_open ||
        !p_kernel_write ||
        !p_filp_close ||
        !p_cam_mem_get_cpu_buf ||
        !addr_get_io_buf ||
        !addr_vfe_out_done) {

        pr_err("cam-raw-dump: symbol lookup failed\n");
        return -1;
    }


    if (hook_wrap3(
        (void *)addr_get_io_buf,
        before_get_io_buf,
        after_get_io_buf,
        NULL)) {

        pr_err("cam-raw-dump: hook io buf failed\n");
        return -1;
    }


    if (hook_wrap2(
        (void *)addr_vfe_out_done,
        before_vfe_out_done,
        NULL,
        NULL)) {

        pr_err("cam-raw-dump: hook vfe failed\n");
        return -1;
    }


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

        capture_status = 1;
        dump_count = 0;

        pr_info("cam-raw-dump: control0 armed, capture_status=%d\n", capture_status);

        compat_copy_to_user(
            out_msg,
            "armed",
            6
        );

    } else if (args[0] == 's') {

        pr_info("cam-raw-dump: status=%d hookA_before=%u hookA_after=%u "
                "hookB_total=%u hookB_wrongstatus=%u hookB_nohandle=%u hookB_getcpufail=%u\n",
                capture_status, cnt_hookA_before, cnt_hookA_after,
                cnt_hookB_total, cnt_hookB_wrong_status, cnt_hookB_no_handle, cnt_hookB_getcpu_fail);

        char buf[16] = "status=";

        buf[7] = '0' + capture_status;
        buf[8] = '\0';


        compat_copy_to_user(
            out_msg,
            buf,
            9
        );
    }


    return 0;
}



static long cam_kpm_exit(void *reserved)
{
    if (addr_get_io_buf)
        unhook((void *)addr_get_io_buf);


    if (addr_vfe_out_done)
        unhook((void *)addr_vfe_out_done);


    pr_info("cam-raw-dump exit\n");

    return 0;
}



KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
