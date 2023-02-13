#include <stdio.h>
#include <unistd.h>
#include <string>
#include <sys/stat.h>
#include <sys/system_properties.h>

#include "procfp.hpp"
#include "logging.hpp"
#include "utils.hpp"
#include "magiskhide_util.hpp"

#include "debug.hpp"

const char *MAGISKTMP = nullptr;

static int myself;

void kill_other(struct stat me){
    crawl_procfs([=](int pid) -> bool {
        struct stat st;
        char path[128];
        sprintf(path, "/proc/%d/exe", pid);
        if (stat(path,&st)!=0)
            return true;
        if (pid == myself)
            return true;
        if (st.st_dev == me.st_dev && st.st_ino == me.st_ino) {
#ifdef DEBUG
            fprintf(stderr, "Killed: %d\n", pid);
#endif
            kill(pid, SIGKILL);
        }
        return true;
    });
}

int main(int argc, char **argv) {
    if (getuid() != 0)
        return -1;

    if (switch_mnt_ns(1))
        return -1;

    set_nice_name("magiskhide_daemon");
    MAGISKTMP = getenv("MAGISKTMP");
    if (!MAGISKTMP) MAGISKTMP="/sbin";

    struct stat me;
    myself = getpid();

    if (stat("/proc/self/exe", &me) != 0)
        return 1;

    kill_other(me);

    if (fork_dont_care() == 0) {
#ifdef DEBUG
        fprintf(stderr, "New hide daemon: %d\n", getpid());
        fprintf(stderr, "Magisk tmpfs path is: %s\n", MAGISKTMP);
#endif
        LOGI("** MagiskHide daemon started\n");

        int pid = getpid();
        char buf[1024] = { '\0' };

        // escape from cgroup
        switch_cgroup("/acct", pid);
        switch_cgroup("/dev/cg2_bpf", pid);
        switch_cgroup("/sys/fs/cgroup", pid);
        __system_property_get("ro.config.per_app_memcg", buf);
        if (strcmp(buf, "false") != 0) {
            switch_cgroup("/dev/memcg/apps", pid);
        }

        // run daemon
        proc_monitor();
        _exit(0);
    }
    return 0;
}
