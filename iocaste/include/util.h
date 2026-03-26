#ifndef iocaste_util_h
#define iocaste_util_h

#include "common.h"

#define PROC_PIDPATHINFO            11
#define PROC_PIDPATHINFO_SIZE       1024
#define PROC_PIDPATHINFO_MAXSIZE    (4*1024)
#define PROC_ALL_PIDS               1

typedef struct {
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
} patches_t;

extern CFDictionaryRef _CFCopySystemVersionDictionary(void);
extern int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
extern int proc_name(int pid, void * buffer, uint32_t buffersize);
extern struct mach_header _mh_execute_header;
extern char **environ;

void *load_file(const char *path, uint32_t *size);
int remove_at_path(const char *path);
int copy_file(const char *from, void *to);
int move_file(const char *from, void *to, bool same_partition);
void sync_path(const char *path);
void sync_volume(const char *path);
int edit_plist(const char *path, void (^action)(CFMutableDictionaryRef plist));
int create_file(const char *path, mode_t mode, uid_t uid, gid_t gid);
void *load_embedded_file(const char *name, size_t *size);
void get_ios_version(uint32_t *output);

#endif /* iocaste_util_h */