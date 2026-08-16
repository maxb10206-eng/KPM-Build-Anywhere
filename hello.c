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
KPM_DESCRIPTION("Camera RDI raw data extractor - chunked full-frame writer");

#define O_WRONLY 00000001
#define O_CREAT  00000100
#define O_TRUNC  00001000

#define CHUNK_SIZE      (64 * 1024)
#define SIZE_THRESHOLD  (1 * 1024 * 1024)
#define TARGET_ARG1     0x2a161

static unsigned char chunk_buf[CHUNK_SIZE];

/* Captured camera buffer information */
static volatile int32_t captured_handle;
static volatile size_t captured_len;

/*
 * 0 = idle
 * 1 = armed
 * 2 = target frame found, waiting for 'w'
 * 3 = full frame written
 */
static volatile char capture_status;

/* Kernel symbols */
static void *(*p_filp_open)(const char *, int, unsigned short);
static long (*p_kernel_write)(void *, const void *, unsigned long, long long *);
static int (*p_filp_close)(void *, void *);
static int (*p_cam_mem_get_cpu_buf)(int32_t, uintptr_t *, size_t *);

/* Hook address */
static unsigned long addr_get_io_buf;

/* Statistics */
static volatile unsigned int cnt_hookA_before;
static volatile unsigned int cnt_hookA_after;
static volatile unsigned int cnt_too_small;
static volatile unsigned int cnt_capture;
static volatile unsigned int cnt_write_ok;
static volatile unsigned int cnt_write_fail;
static volatile size_t max_len_seen;


/* Linux ERR_PTR check */
static int is_err_ptr(void *ptr)
{
    return (unsigned long)ptr >= (unsigned long)-4095;
}


/*
 * Hook before:
 * save arg0 and arg1 for the after callback.
 */
static void before_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_before++;

    args->local.data0 = args->arg0;
    args->local.data1 = args->arg1;
}


/*
 * Hook after:
 * only identify the target buffer.
 *
 * No large memcpy and no file I/O here.
 */
static void after_get_io_buf(hook_fargs3_t *args, void *udata)
{
    cnt_hookA_after++;

    if (capture_status != 1)
        return;

    int32_t buf_handle = (int32_t)args->local.data0;
    uint64_t raw_arg1 = (uint64_t)args->local.data1;

    if (!buf_handle || !p_cam_mem_get_cpu_buf)
        return;

    if (raw_arg1 != TARGET_ARG1)
        return;

    uintptr_t vaddr = 0;
    size_t len = 0;

    if (p_cam_mem_get_cpu_buf(buf_handle, &vaddr, &len))
        return;

    if (!vaddr || !len)
        return;

    if (len > max_len_seen)
        max_len_seen = len;

    /*
     * Ignore the small 2a161 buffers such as 32KB/69KB.
     * The actual RAW frame observed previously was >5MB.
     */
    if (len < SIZE_THRESHOLD) {
        cnt_too_small++;
        return;
    }

    /*
     * Do not copy the frame here.
     * Just remember the buffer handle.
     */
    captured_handle = buf_handle;
    captured_len = len;

    cnt_capture++;
    capture_status = 2;

    pr_info(
        "cam-raw-dump: TARGET frame found! "
        "handle=%d arg1=%llx len=%zu\n",
        buf_handle,
        raw_arg1,
        len
    );
}


/*
 * Write one captured frame to disk in 64KB chunks.
 *
 * The buffer address/length are refreshed through
 * cam_mem_get_cpu_buf() before writing, so we don't rely
 * solely on the vaddr captured earlier.
 */
static int write_captured_frame_to_disk(void)
{
    uintptr_t vaddr = 0;
    size_t len = 0;

    if (!captured_handle || !p_cam_mem_get_cpu_buf)
        return -1;

    if (p_cam_mem_get_cpu_buf(
            captured_handle,
            &vaddr,
            &len) != 0) {

        pr_err(
            "cam-raw-dump: refresh buffer failed handle=%d\n",
            captured_handle
        );

        return -1;
    }

    if (!vaddr || !len) {
        pr_err(
            "cam-raw-dump: invalid refreshed buffer "
            "vaddr=%p len=%zu\n",
            (void *)vaddr,
            len
        );

        return -1;
    }

    /*
     * Use the refreshed length rather than the old cached length.
     */
    captured_len = len;

    void *f = p_filp_open(
        "/data/local/tmp/cam_frame.raw",
        O_CREAT | O_WRONLY | O_TRUNC,
        0644
    );

    if (is_err_ptr(f)) {
        pr_err("cam-raw-dump: open failed\n");
        return -1;
    }

    long long pos = 0;
    uintptr_t src = vaddr;
    size_t remain = len;

    while (remain > 0) {

        size_t chunk_len =
            remain > CHUNK_SIZE
                ? CHUNK_SIZE
                : remain;

        /*
         * Copy only 64KB at a time.
         */
        memcpy(
            chunk_buf,
            (void *)src,
            chunk_len
        );

        /*
         * kernel_write() may perform a partial write.
         * Keep writing until this chunk is complete.
         */
        size_t done = 0;

        while (done < chunk_len) {

            long ret = p_kernel_write(
                f,
                chunk_buf + done,
                chunk_len - done,
                &pos
            );

            if (ret <= 0) {

                pr_err(
                    "cam-raw-dump: write failed "
                    "ret=%ld done=%zu chunk=%zu\n",
                    ret,
                    done,
                    chunk_len
                );

                p_filp_close(f, NULL);
                return -1;
            }

            done += (size_t)ret;
        }

        src += chunk_len;
        remain -= chunk_len;
    }

    p_filp_close(f, NULL);

    pr_info(
        "cam-raw-dump: full frame written size=%zu\n",
        len
    );

    return 0;
}


/*
 * KPM init
 */
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

    if (!p_filp_open ||
        !p_kernel_write ||
        !p_filp_close ||
        !p_cam_mem_get_cpu_buf ||
        !addr_get_io_buf) {

        pr_err(
            "cam-raw-dump: symbol lookup failed\n"
        );

        return -1;
    }

    if (hook_wrap3(
            (void *)addr_get_io_buf,
            before_get_io_buf,
            after_get_io_buf,
            NULL)) {

        pr_err(
            "cam-raw-dump: hook io buf failed\n"
        );

        return -1;
    }

    pr_info("cam-raw-dump: init ok\n");

    return 0;
}


/*
 * KPM control
 *
 * c = arm capture
 * w = write captured frame
 * s = status
 */
static long cam_kpm_control0(
    const char *args,
    char __user *out_msg,
    int outlen)
{
    if (!args)
        return -1;

    if (args[0] == 'c') {

        capture_status = 1;
        captured_handle = 0;
        captured_len = 0;

        pr_info(
            "cam-raw-dump: control0 armed\n"
        );

        compat_copy_to_user(
            out_msg,
            "armed",
            6
        );

    } else if (args[0] == 'w') {

        if (capture_status != 2 ||
            !captured_handle) {

            pr_info(
                "cam-raw-dump: no captured frame\n"
            );

            compat_copy_to_user(
                out_msg,
                "no_frame",
                9
            );

            return 0;
        }

        int rc =
            write_captured_frame_to_disk();

        if (rc == 0) {

            cnt_write_ok++;
            capture_status = 3;

            compat_copy_to_user(
                out_msg,
                "write_ok",
                9
            );

        } else {

            cnt_write_fail++;

            compat_copy_to_user(
                out_msg,
                "write_fail",
                11
            );
        }

    } else if (args[0] == 's') {

        pr_info(
            "cam-raw-dump: status=%d "
            "hookA_before=%u "
            "hookA_after=%u "
            "too_small=%u "
            "capture=%u "
            "write_ok=%u "
            "write_fail=%u "
            "captured_handle=%d "
            "captured_len=%zu "
            "max_len_seen=%zu\n",
            capture_status,
            cnt_hookA_before,
            cnt_hookA_after,
            cnt_too_small,
            cnt_capture,
            cnt_write_ok,
            cnt_write_fail,
            captured_handle,
            captured_len,
            max_len_seen
        );

        char buf[16] = "status=";

        buf[7] =
            '0' + capture_status;

        buf[8] = '\0';

        compat_copy_to_user(
            out_msg,
            buf,
            9
        );
    }

    return 0;
}


/*
 * KPM exit
 */
static long cam_kpm_exit(void *reserved)
{
    if (addr_get_io_buf)
        unhook((void *)addr_get_io_buf);

    pr_info(
        "cam-raw-dump exit\n"
    );

    return 0;
}


KPM_INIT(cam_kpm_init);
KPM_CTL0(cam_kpm_control0);
KPM_EXIT(cam_kpm_exit);
