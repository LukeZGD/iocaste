#include "iocaste.h"
#include "util.h"

int uninstall(void) {
    remove_at_path("/mnt1/tmp/iocaste.bin");
    remove_at_path("/mnt1/private/etc/iocaste.conf");
    remove_at_path("/mnt1/private/etc/racoon/stage2");

    iocaste_restore_backup();
    remove_at_path("/mnt1/private/var/root/iocaste");

    sync_volume("/mnt1/private/var");
    sync_volume("/mnt1/");
    usleep(250000);
    return 0;
}

int update(void) {
    if (iocaste_init() != 0) {
        fprintf(stderr, "[-] failed to initialize, untether will NOT be updated\n");
        return -1;
    }
    
    remove_at_path("/mnt1/private/etc/racoon/racoon.conf");
    remove_at_path("/mnt1/private/etc/dhcpd.conf");
    remove_at_path("/mnt1/private/var/root/iocaste/stage1");
    remove_at_path("/mnt1/private/var/root/iocaste/stage2.bin");
    remove_at_path("/mnt1/private/var/root/iocaste/stage3.bin");

    mkdir("/mnt1/private/var/root/iocaste/stage1", 0777);
    chown("/mnt1/private/var/root/iocaste/stage1", 0, 0);
    int status = -1;

    if (gen_stage1() != 0) {
        fprintf(stderr, "[-] failed to create stage1\n");
        goto done;
    }

    if (gen_stage2() != 0) {
        fprintf(stderr, "[-] failed to create stage2\n");
        goto done;
    }

    if (gen_stage3() != 0) {
        fprintf(stderr, "[-] failed to create stage3\n");
        goto done;
    }

    sync_volume("/mnt1/private/var");
    sync_volume("/mnt1/");
    usleep(250000);
    status = 0;

done:
    if (status == 0) return 0;
    fprintf(stderr, "[-] failed to update untether, undoing all changes...\n");
    uninstall();
    return -1;
}


int install(void) {
    if (access("/mnt1/private/var/root/iocaste", F_OK) == 0) return update();
    fprintf(stdout, "[*] installing untether, this will take a few minutes...\n");
    
    if (iocaste_init() != 0) {
        fprintf(stderr, "[-] failed to initialize, untether will NOT be installed\n");
        return -1;
    }
    int status = -1;

    mkdir("/mnt1/private/var/root/iocaste", 0777);
    chown("/mnt1/private/var/root/iocaste", 0, 0);
    mkdir("/mnt1/private/var/root/iocaste/stage1", 0777);
    chown("/mnt1/private/var/root/iocaste/stage1", 0, 0);
    mkdir("/mnt1/Library/LaunchDaemons", 0777);
    chown("/mnt1/Library/LaunchDaemons", 0, 0);

    if (iocaste_create_backup() != 0) {
        fprintf(stderr, "[-] failed to create backup\n");
        goto done;
    }

    FILE *file = fopen("/mnt1/private/etc/fstab", "w+");
    if (file == NULL) {
        fprintf(stderr, "[-] failed to edit fstab\n");
        goto done;
    }

    fprintf(file, "/mnt1/dev/disk0s1s1 / hfs ro 0 1\n");
    fprintf(file, "/mnt1/dev/disk0s1s2 /private/var hfs rw,nodev 0 2\n");
    fflush(file);
    fclose(file);

    chmod("/mnt1/private/etc/fstab", 0644);
    chown("/mnt1/private/etc/fstab", 0, 0);
    sync_path("/mnt1/private/etc/fstab");

    file = fopen("/mnt1/private/var/root/iocaste/patches.bin", "w+");
    if (file == NULL) {
        fprintf(stderr, "[-] failed to create patches.bins\n");
        goto done;
    }

    fwrite(&iocaste->offsets.kernel, sizeof(patches_t), 1, file);
    fflush(file);
    fclose(file);

    chmod("/mnt1/private/var/root/iocaste/patches.bin", 0777);
    chown("/mnt1/private/var/root/iocaste/patches.bin", 0, 0);
    sync_path("/mnt1/private/var/root/iocaste/patches.bin");

    remove_at_path("/mnt1/private/etc/racoon/racoon.conf");
    remove_at_path("/mnt1/private/etc/dhcpd.conf");
    move_file("/mnt1/usr/libexec/wifiFirmwareLoader", "/mnt1/usr/libexec/wifiFirmwareLoader_orig", true);
    move_file("/mnt1/System/Library/LaunchDaemons/com.apple.SpringBoard.plist", "/mnt1/Library/LaunchDaemons/com.apple.SpringBoard.plist", true);
    symlink("/mnt1/usr/libexec/dhcpd", "/mnt1/usr/libexec/wifiFirmwareLoader");
    symlink("/mnt1/private/var/root/iocaste/stage2.bin", "/mnt1/private/etc/racoon/stage2");
    
    if (gen_stage1() != 0) {
        fprintf(stderr, "[-] failed to create stage1\n");
        goto done;
    }

    if (gen_stage2() != 0) {
        fprintf(stderr, "[-] failed to create stage2\n");
        goto done;
    }

    if (gen_stage3() != 0) {
        fprintf(stderr, "[-] failed to create stage3\n");
        goto done;
    }

    sync_volume("/mnt1/private/var");
    sync_volume("/mnt1/");
    usleep(250000);
    status = 0;

done:
    if (status == 0) return 0;
    fprintf(stderr, "[-] failed to install untether, undoing all changes...\n");
    uninstall();
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 2) return -1;
    if (strcmp(argv[1], "install") == 0) return install();
    if (strcmp(argv[1], "uninstall") == 0) return uninstall();
    if (strcmp(argv[1], "update") == 0) return update();
    return 0;
}
