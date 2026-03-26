#include "util.h"
#include "oob_entry.h"
#include "memory.h"

void *(*IOSurfaceCreate)(CFDictionaryRef) = NULL;
void *(*IOSurfaceGetBaseAddress)(void *) = NULL;
int (*IOServiceOpen)(mach_port_t, mach_port_t, uint32_t, mach_port_t *) = NULL;
static FILE *log_file = 0;

int init_io(void) {
    void *io_handle = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW);
    if (io_handle == NULL) {
        io_handle = dlopen("/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface", RTLD_NOW);
        if (io_handle == NULL) return -1;
    }

    if ((IOSurfaceCreate = dlsym(io_handle, "IOSurfaceCreate")) == NULL) return -1;
    if ((IOSurfaceGetBaseAddress = dlsym(io_handle, "IOSurfaceGetBaseAddress")) == NULL) return -1;
    if ((IOServiceOpen = dlsym(io_handle, "IOServiceOpen")) == NULL) return -1;
    return 0;
}

void get_ios_version(uint32_t *output) {
    char str[32] = {0};
    CFDictionaryRef dict = _CFCopySystemVersionDictionary();
    CFStringRef version = CFDictionaryGetValue(dict, CFSTR("ProductVersion"));
    CFStringGetCString(version, str, 32, kCFStringEncodingUTF8);
    
    sscanf(str, "%d.%d.%d", &output[0], &output[1], &output[2]);
    CFRelease(dict);
}

CFNumberRef CFNUM(uint32_t value) {
    return CFNumberCreate(NULL, kCFNumberIntType, (void *)&value);
}

mach_port_t create_mach_port(void) {
    mach_port_t port = MACH_PORT_NULL;
    mach_port_t task = mach_task_self();
    mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &port);
    mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND);
    return port;
}

int init_offsets(void) {
    get_ios_version(kinfo->version);
    if (kinfo->version[0] < 3 || kinfo->version[0] > 10) return -1;
    
    size_t size = sizeof(kinfo->mem_size);
    sysctlbyname("hw.physmem", &kinfo->mem_size, &size, NULL, 0);
    kinfo->mem_size &= 0xfff00000;

    switch (kinfo->version[0]) {
        case 9:
            kinfo->offsets.task.ref_count = 0xc;
            kinfo->offsets.task.bsd_info = 0x200;
            kinfo->offsets.ipc_port.ip_references = 0x4;
            kinfo->offsets.ipc_port.ip_kobject = 0x50;
            kinfo->offsets.ipc_port.size = 0x78;
            kinfo->kernel_static_base = 0x80001000;
            kinfo->kernel_phys_base = 0x80001000;
            kinfo->mem_base = 0x80000000;
            break;
        default:
            break;
    }
    return 0;
}

void killall(const char *process_name) {
    int count = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0) + 100;
    if (count <= 0) return;

    pid_t *pids = calloc(1, sizeof(pid_t) * count);
    count = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pid_t) * count);
    if (count <= 0) {
        free(pids);
        return;
    }

    char *name = calloc(1, PROC_PIDPATHINFO_MAXSIZE+1);
    for (int i = 0; i < count; i++) {
        bzero(name, PROC_PIDPATHINFO_MAXSIZE+1);
        pid_t pid = pids[i];

        if (proc_name(pid, name, PROC_PIDPATHINFO_MAXSIZE) <= 0) continue;
        if (strncmp((const char *)name, process_name, PROC_PIDPATHINFO_MAXSIZE) == 0) {
            if (pid != getpid()) {
                kill(pid, SIGKILL);
            }
        }
    }

    free(name);
    free(pids);
}

void launchctl_unload(const char *label) {
    char service_name[PATH_MAX] = {0};
    snprintf(service_name, PATH_MAX-1, "system/%s", label);

    char plist_path[PATH_MAX] = {0};
    snprintf(plist_path, PATH_MAX-1, "/System/Library/LaunchDaemons/%s.plist", label);

    char *unload_args[] = {"/bin/launchctl", "unload", plist_path, NULL};
    char *bootout_args[] = {"/bin/launchctl", "bootout", service_name, NULL};
    pid_t pid = -1;
    int status = -1;
 
    int rv = posix_spawn(&pid, unload_args[0], NULL, NULL, unload_args, environ);
    if (rv == 0 && pid != -1) {
        do { if (waitpid(pid, &status, 0) == -1) break; }
        while (!WIFEXITED(status) && !WIFSIGNALED(status));
    }

    pid = -1;
    status = -1;
    rv = posix_spawn(&pid, bootout_args[0], NULL, NULL, bootout_args, environ);
    if (rv == 0 && pid != -1) {
        do { if (waitpid(pid, &status, 0) == -1) break; }
        while (!WIFEXITED(status) && !WIFSIGNALED(status));
    }
}

int load_user_daemons(void) {
    char *args[] = {"/bin/launchctl", "load", "/Library/LaunchDaemons", NULL};
    pid_t pid = -1;
    int status = -1;

    int rv = posix_spawn(&pid, args[0], NULL, NULL, args, environ);
    if (rv != 0 || pid == -1) return rv;
    
    do { if (waitpid(pid, &status, 0) == -1) return status; }
    while (!WIFEXITED(status) && !WIFSIGNALED(status));
    return status;
}

int load_run_commands(void) {
    DIR *dir = opendir("/etc/rc.d");
    if (dir == NULL) return 0;

    struct dirent *entry = NULL;
    char path_buf[PATH_MAX] = {0};
    char *args[] = {path_buf, NULL};

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        bzero(path_buf, PATH_MAX);
        snprintf(path_buf, PATH_MAX-1, "/etc/rc.d/%s", entry->d_name);

        pid_t pid = -1;
        int status = -1;
        int rv = posix_spawn(&pid, path_buf, NULL, NULL, args, environ);
        if (rv != 0 || pid == -1) continue;

        do { if (waitpid(pid, &status, 0) == -1) continue; }
        while (!WIFEXITED(status) && !WIFSIGNALED(status));
    }

    closedir(dir);
    return 0;
}

int load_daemons(void) {
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    usleep(250000);

    DIR *dir = opendir("/Library/LaunchDaemons");
    if (dir != NULL) {
        struct dirent *entry = NULL;
        char path_buf[PATH_MAX] = {0};

        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
            if (strstr(entry->d_name, ".plist") == NULL) continue;

            bzero(path_buf, PATH_MAX);
            snprintf(path_buf, PATH_MAX, "/Library/LaunchDaemons/%s", entry->d_name);
            
            chmod(path_buf, 0644);
            chown(path_buf, 0, 0);
        }
    }

    closedir(dir);
    sync();

    usleep(100000);
    load_run_commands();
    load_user_daemons();

    usleep(100000);
    killall("installd");
    chmod("/usr/libexec/wifiFirmwareLoader_orig", 0755);
    chown("/usr/libexec/wifiFirmwareLoader_orig", 0, 0);

    pid_t pid = -1;
    int status = -1;
    char *args[] = {"/usr/libexec/wifiFirmwareLoader_orig", NULL};

    int rv = posix_spawn(&pid, args[0], NULL, NULL, args, environ);
    if (rv == 0 && pid != -1) {
        do { if (waitpid(pid, &status, 0) == -1) break; }
        while (!WIFEXITED(status) && !WIFSIGNALED(status));
    }

    launchctl_unload("com.apple.wifiFirmwareLoader");
    launchctl_unload("com.apple.racoon");
    killall("racoon");
    killall("dhcpd");
    exit(0);
}
