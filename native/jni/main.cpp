#include <stdio.h>
#include <unistd.h>
#include <string>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <libgen.h>

#include "procfp.hpp"
#include "logging.hpp"
#include "utils.hpp"
#include "magiskhide_util.hpp"

#include "debug.hpp"

const char *MAGISKTMP = nullptr;
bool new_magic_mount = false;
bool trace_log = false;
int SDK_INT = 0;
dev_t worker_dev = 0;

int log_fd = -1;

static int myself;

void kill_other(struct stat me){
    crawl_procfs([=](int pid) -> bool {
        struct stat st;
        char path[128];
        char cmdline[1024];
        snprintf(path, 127, "/proc/%d/exe", pid);
        if (stat(path,&st)!=0)
            return true;
        snprintf(path, 127, "/proc/%d/cmdline", pid);
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

void find_magiskd() {
    crawl_procfs([=](int pid) -> bool {
        struct stat st;
        char path[128];
        char cmdline[1024];
        snprintf(path, 127, "/proc/%d", pid);
        if (stat(path,&st)!=0)
            return true;
        snprintf(path, 127, "/proc/%d/cmdline", pid);
        FILE *fp = fopen(path, "re");
        if (fp == nullptr)
            return true;
        fgets(cmdline, sizeof(cmdline), fp);
        fclose(fp);
        snprintf(path, 127, "/proc/%d/exe", pid);
        if (strcmp(cmdline, "magiskd") == 0 && parse_ppid(pid) == 1 && st.st_uid == 0) {
            MAGISKTMP = dirname(realpath(path, nullptr));
            return false;
        }
        return true;
    });
}

int main(int argc, char **argv) {
    if (getuid() != 0)
        return -1;

    if (switch_mnt_ns(1))
        return -1;

    find_magiskd();
    if (MAGISKTMP == nullptr) {
        LOGI("cannot find magiskd\n");
        return -1;
    }

    if (argc >= 2 && strcmp(argv[1], "exec") == 0) {
        if (argc >= 3 && unshare(CLONE_NEWNS) == 0) {
            char buf[1024];
            snprintf(buf, sizeof(buf)-1, "%s/.magisk/worker", MAGISKTMP);
            if (access(buf, F_OK) == 0) {
                new_magic_mount = true;
                struct stat st{};
                stat(buf, &st);
                worker_dev = st.st_dev;
            }
            mount(nullptr, "/", nullptr, MS_PRIVATE | MS_REC, nullptr);
            hide_unmount();
            execvp(argv[2], argv + 2);
        }
        return 1;
    }

    struct stat me;
    myself = getpid();

    if (argc >= 2 && strcmp(argv[1], "--test") == 0) {
        proc_monitor();
        return 0;
    }

    if (stat("/proc/self/exe", &me) != 0)
        return 1;

    int pipe_fd[2];
    if (pipe(pipe_fd) < 0) {
        fprintf(stderr, "Broken pipe\n");
        return -1;
    }

    kill_other(me);
    set_nice_name("magiskhide_daemon");

    if (fork_dont_care() == 0) {
        int pid = getpid();

        log_fd = open("/cache/magisk.log", O_RDWR | O_CREAT | O_APPEND, 0666);

        LOGI("** MagiskHide daemon started\n");
        LOGI("Magisk tmpfs path is: %s\n", MAGISKTMP);
        write(pipe_fd[1], &pid, sizeof(pid));

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

        setsid();

        // escape from cgroup
        switch_cgroup("/acct", pid);
        switch_cgroup("/dev/cg2_bpf", pid);
        switch_cgroup("/sys/fs/cgroup", pid);
        __system_property_get("ro.config.per_app_memcg", buf);
        if (strcmp(buf, "false") != 0) {
            switch_cgroup("/dev/memcg/apps", pid);
        }
        buf[0] = '\0';
        __system_property_get("ro.build.version.sdk", buf);
        SDK_INT = parse_int(buf);

        snprintf(buf, sizeof(buf)-1, "%s/.magisk/worker", MAGISKTMP);
        if (access(buf, F_OK) == 0) {
            new_magic_mount = true;
            struct stat st{};
            stat(buf, &st);
            worker_dev = st.st_dev;
        }


        // run daemon
        proc_monitor();
        _exit(0);
    }
    int daemon = -1;
    read(pipe_fd[0], &daemon, sizeof(daemon));
    close(pipe_fd[0]);
    close(pipe_fd[1]);

#ifdef DEBUG
    fprintf(stderr, "Launched hide daemon: %d\n", daemon);
#endif

    return 0;
}
