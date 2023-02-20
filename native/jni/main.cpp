#include <stdio.h>
#include <unistd.h>
#include <string>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <signal.h>
#include <fcntl.h>

#include "procfp.hpp"
#include "logging.hpp"
#include "utils.hpp"
#include "magiskhide_util.hpp"

#include "debug.hpp"

const char *MAGISKTMP = nullptr;
bool new_magic_mount = false;

int log_fd = -1;

static int myself;

void kill_other(struct stat me){
    crawl_procfs([=](int pid) -> bool {
        struct stat st;
        char path[128];
        char cmdline[1024];
        sprintf(path, "/proc/%d/exe", pid);
        if (stat(path,&st)!=0)
            return true;
        sprintf(path, "/proc/%d/cmdline", pid);
        FILE *fp = fopen(path, "re");
        if (fp == nullptr)
            return true;
        fgets(cmdline, sizeof(cmdline), fp);
        fclose(fp);
        if (pid == myself)
            return true;
        if ((st.st_dev == me.st_dev && st.st_ino == me.st_ino) ||
            (st.st_size == me.st_size &&  strcmp(cmdline, "magiskhide_daemon") == 0)) {
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

    MAGISKTMP = getenv("MAGISKTMP");
    if (!MAGISKTMP) MAGISKTMP="/sbin";

    if (argc >= 2 && strcmp(argv[1], "exec")) {
        if (argc >= 3 && unshare(CLONE_NEWNS) == 0) {
            char buf[1024];
            snprintf(buf, sizeof(buf)-1, "%s/.magisk/worker", MAGISKTMP);
            if (access(buf, F_OK) == 0)
                new_magic_mount = true;
            hide_unmount();
       	    execvp(argv[2], argv + 2);
        }
        return 1;
    }

    struct stat me;
    myself = getpid();
    set_nice_name("magiskhide_daemon");

    if (stat("/proc/self/exe", &me) != 0)
        return 1;

    int pipe_fd[2];
    if (pipe(pipe_fd) < 0) {
        fprintf(stderr, "Broken pipe\n");
        return -1;
    }

    kill_other(me);

    if (fork_dont_care() == 0) {
        int pid = getpid();
        write(pipe_fd[1], &pid, sizeof(pid));

        log_fd = open("/cache/magisk.log", O_RDWR | O_CREAT | O_APPEND, 0666);

        LOGI("** MagiskHide daemon started\n");
        LOGI("Magisk tmpfs path is: %s\n", MAGISKTMP);

        struct pstream pst;
        char *magiskcmd[] = { strdup("magisk"), strdup("--denylist"), strdup("exec"), strdup("true"), nullptr };
        int ret = pst.open(magiskcmd);

        free(magiskcmd[0]);
        free(magiskcmd[1]);
        free(magiskcmd[2]);
        free(magiskcmd[3]);

        pst.close_pipe();
        if (ret <= 0) {
            LOGW("denylist: daemon error or does not exist\n");
            _exit(-1);
        }

        int status = -1;
        waitpid(pst.pid, &status, 0);
        if (status != 0) {
            LOGW("denylist: daemon error or does not exist\n");
            _exit(-1);
        }

        signal(SIGTERM, SIG_IGN);
        signal(SIGUSR1, SIG_IGN);
        signal(SIGUSR2, SIG_IGN);

        char buf[1024] = { '\0' };

        // escape from cgroup
        switch_cgroup("/acct", pid);
        switch_cgroup("/dev/cg2_bpf", pid);
        switch_cgroup("/sys/fs/cgroup", pid);
        __system_property_get("ro.config.per_app_memcg", buf);
        if (strcmp(buf, "false") != 0) {
            switch_cgroup("/dev/memcg/apps", pid);
        }

        snprintf(buf, sizeof(buf)-1, "%s/.magisk/worker", MAGISKTMP);
        if (access(buf, F_OK) == 0)
            new_magic_mount = true;
        // run daemon
        proc_monitor();
        _exit(0);
    }
    int daemon = -1;
    read(pipe_fd[0], &daemon, sizeof(daemon));
    close(pipe_fd[0]);
    close(pipe_fd[1]);

#ifdef DEBUG
    fprintf(stderr, "New hide daemon: %d\n", daemon);
#endif

    return 0;
}
