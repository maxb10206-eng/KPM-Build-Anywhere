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
static unsigned char chunk_buf[CHUNK_SIZE];

static void *(*p_filp_open)(const char *, int, unsigned short) = NULL;
static long (*p_kernel_write)(void *, const void *, unsigned long, long long *) = NULL;
static int (*p_filp_close)(void *, void *) = NULL;
static int (*p_cam_mem_get_cpu_buf)(int32_t, uintptr_t *, size_t *) = NULL;

static long (*p_hook_wrap2)(void *func, void *before, void *after, void *udata) = NULL;
static long (*p_hook_wrap3)(void *func, void *before, void *after, void *udata) = NULL;
static void (*p_unhook)(void *func) = NULL;

static unsigned long addr_get_io_buf = 0;
static unsigned long addr_vfe_out_done = 0;

#define MAX_MAP_ENTRIES 64
struct iova_map_entry { uint32_t iova; int32_t buf_handle; };
static struct iova_map_entry iova_map[MAX_MAP_ENTRIES];
static int map_idx = 0;

static void record_iova_mapping(uint32_t iova, int32_t handle)
{
    iova_map[map_idx].iova = iova;
    iova_map[map_idx].buf_handle = handle;
    map_idx = (map_idx + 1) % MAX_MAP_ENTRIES;
}

static int32_t lookup_buf_handle(uint32_t iova)
{
    int i;
    for (i = 0; i < MAX_MAP_ENTRIES; i++) {
        int idx = (map_idx - 1 - i + MAX_MAP_ENTRIES) % MAX_MAP_ENTRIES;
        if (iova_map[idx].iova == iova) return iova_map[idx].buf_handle;
    }
    return 0;
}

static int is_err_ptr(void *ptr)
{
    return (unsigned long)ptr >= (unsigned long)-4095;
}

static volatile int capture_status = 0;

static void before_get_io_buf(hook_fargs3_t *args, void *udata)
{
    args->local.data0 = args->arg0;
}
static void after_get_io_buf(hook_fargs3_t *args, void *udata)
{
    int32_t buf_handle = (int32_t)args->local.data0;
    dma_addr_t *iova_ptr = (dma_addr_t *)args->arg2;
    if (iova_ptr && buf_handle)
        record_iova_mapping((uint32_t)(*iova_ptr), buf_handle);
}

#define CAM_NUM_OUT_PER_COMP_IRQ_MAX 6
struct cam_isp_hw_done_event_data {
    uint32_t num_handles;
    uint32_t resource_handle[CAM_NUM_OUT_PER_COMP_IRQ_MAX];
    uint32_t last_consumed_addr[CAM_NUM_OUT_PER_COMP_IRQ_MAX];
    uint64_t timestamp;
};

static void before_vfe_out_done(hook_fargs2_t *args, void *udata)
{
    struct cam_isp_hw_done_event_data *evt =
        (struct cam_isp_hw_done_event_data *)args->arg1;

    if (capture_status != 1 || !evt || evt->num_handles == 0) return;
    if (!p_cam_mem_get_cpu_buf) return;

    uint32_t iova = evt->last_consumed_addr[0];
    int32_t buf_handle = lookup_buf_handle(iova);
    if (!buf_handle) return;

    uintptr_t vaddr = 0; size_t len = 0;
    if (p_cam_mem_get_cpu_buf(buf_handle, &vaddr, &len) != 0 || !vaddr) return;

    void *f = p_filp_open("/data/local/tmp/cam_frame.raw",
                           O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (is_err_ptr(f)) { pr_err("cam-raw-dump: open failed\n"); return; }

    long long pos = 0;
    size_t remain = len;
    uintptr_t src = vaddr;
    while (remain > 0) {
        size_t n = remain > CHUNK_SIZE ? CHUNK_SIZE : remain;
        memcpy(chunk_buf, (void *)src, n);
        p_kernel_write(f, chunk_buf, n, &pos);
        src += n;
        remain -= n;
    }
    p_filp_close(f, NULL);
    capture_status = 2;
    pr_info("cam-raw-dump: frame written, size=%zu\n", len);
}

static long cam_kpm_init(const char *args, const char *event, void *reserved)
{
    pr_info("cam-raw-dump: step1 symbol lookup\n");

    p_filp_open = (void *)kallsyms_lookup_name("filp_open");
    p_kernel_write = (void *)kallsyms_lookup_name("kernel_write");
    p_filp_close = (void *)kallsyms_lookup_name("filp_close");
    p_cam_mem_get_cpu_buf = (void *)kallsyms_lookup_name("cam_mem_get_cpu_buf");
    addr_get_io_buf = kallsyms_lookup_name("cam_mem_get_io_buf");
    addr_vfe_out_done = kallsyms_lookup_name("cam_vfe_bus_ver3_handle_vfe_out_done_bottom_half");

    p_hook_wrap2 = (void *)kallsyms_lookup_name("hook_wrap2");
    p_hook_wrap3 = (void *)kallsyms_lookup_name("hook_wrap3");
    p_unhook = (void *)kallsyms_lookup_name("unhook");

    pr_info("cam-raw-dump: step2 hook_wrap2=%p hook_wrap3=%p unhook=%p\n",
            p_hook_wrap2, p_hook_wrap3, p_unhook);

    if (!p_filp_open || !p_kernel_write || !p_filp_close ||
        !p_cam_mem_get_cpu_buf || !addr_get_io_buf || !addr_vfe_out_done ||
        !p_hook_wrap2 || !p_hook_wrap3 || !p_unhook) {
        pr_err("cam-raw-dump: symbol lookup failed\n");
        return -1;
    }

    pr_info("cam-raw-dump: step3 installing hooks\n");
    p_hook_wrap3((void *)addr_get_io_buf, before_get_io_buf, after_get_io_buf, NULL);
    p_hook_wrap2((void *)addr_vfe_out_done, before_vfe_out_done, NULL, NULL);

    pr_info("cam-raw-dump: step4 init ok\n");
    return 0;
}

static long cam_kpm_control0(const char *args, char *__user out_msg, int outlen)
{
    if (!args) return -1;
    if (args[0] == 'c') {
        capture_status = 1;
        compat_copy_to_user(out_msg, "armed", 6);
    } else if (args[0] == 's') {
        // 手动拼字符串,不用snprintf,避开隐式声明风险
        char buf[16] = "status=";
        buf[7] = '0' + (capture_status % 10);
        buf[8] = '\0';
        compat_copy_to_user(out_msg, buf, 9);
    }
    return 0;
}

static long cam_kpm_exit(void *reserved)
{
    if (p_unhook) {
        if (addr_get_io_buf) p_unhook((void *)addr_get_io_buf);
        if (addr_vfe_out_done) p_unhook((void *)addr_vfe_out_done);
    }
    pr_info("cam-raw-dump exit\n");
    return 0;
}

KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
