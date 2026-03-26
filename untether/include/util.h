#ifndef util_h
#define util_h

#include "common.h"

#define IKOT_TASK                   0x00000002
#define	IKOT_HOST                   0x00000003
#define	IKOT_HOST_PRIV              0x00000004
#define IO_BITS_ACTIVE              0x80000000
#define OOL_COUNT                   100
#define PROC_PIDPATHINFO            11
#define PROC_PIDPATHINFO_SIZE       1024
#define PROC_PIDPATHINFO_MAXSIZE    (4*1024)
#define PROC_ALL_PIDS               1

#define koffsetof(struct, entry) kinfo->offsets.struct.entry

typedef struct {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports;
} ool_msg_t;

extern char **environ;
extern int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
extern int proc_name(int pid, void * buffer, uint32_t buffersize);
extern CFDictionaryRef _CFCopySystemVersionDictionary(void);

extern void *(*IOSurfaceCreate)(CFDictionaryRef);
extern void *(*IOSurfaceGetBaseAddress)(void *);
extern int (*IOServiceOpen)(mach_port_t, mach_port_t, uint32_t, mach_port_t *);

int init_io(void);
void get_ios_version(uint32_t *output);
CFNumberRef CFNUM(uint32_t value);
mach_port_t create_mach_port(void);
int init_offsets(void);
void killall(const char *process_name);
void launchctl_unload(const char *label);
int load_user_daemons(void);
int load_run_commands(void);
int load_daemons(void);

#endif /* util_h */
