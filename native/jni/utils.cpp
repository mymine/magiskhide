#include <sys/ptrace.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <string>
#include <iostream>
#include <pthread.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include "logging.hpp"

#include "utils.hpp"

#define READ 0
#define WRITE 1
	
long xptrace(int request, pid_t pid, void *addr, void *data) {
    long ret = ptrace(request, pid, addr, data);
    if (ret < 0)
        PLOGE("ptrace %d", pid);
    return ret;
}

int xinotify_init1(int flags) {
    int ret = inotify_init1(flags);
    if (ret < 0) {
        PLOGE("inotify_init1");
    }
    return ret;
}

int fork_dont_care() {
    if (int pid = fork()) {
        waitpid(pid, nullptr, 0);
        return pid;
    } else if (fork()) {
        _exit(0);
    }
    return 0;
}


int new_daemon_thread(thread_entry entry, void *arg) {
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    errno = pthread_create(&thread, &attr, entry, arg);
    if (errno) {
        PLOGE("pthread_create");
    }
    return errno;
}

int new_daemon_thread(void(*entry)()) {
    thread_entry proxy = [](void *entry) -> void * {
        reinterpret_cast<void(*)()>(entry)();
        return nullptr;
    };
    return new_daemon_thread(proxy, (void *) entry);
}

int parse_int(std::string_view s) {
    int val = 0;
    for (char c : s) {
        if (!c) break;
        if (c > '9' || c < '0')
            return -1;
        val = val * 10 + c - '0';
    }
    return val;
}

int switch_mnt_ns(int pid) {
    char mnt[32];
    snprintf(mnt, sizeof(mnt), "/proc/%d/ns/mnt", pid);
    if (access(mnt, R_OK) == -1) return 1; // Maybe process died..

    int fd, ret;
    fd = open(mnt, O_RDONLY);
    if (fd < 0) return 1;
    // Switch to its namespace
    ret = setns(fd, 0);
    close(fd);
    return ret;
}

bool starts_with(const char *s, const char *ss) {
    const char *str = strstr(s,ss);
    return str != nullptr && str == s;
}

pid_t popen2(char **command, int *infp, int *outfp) {

    int p_stdin[2], p_stdout[2];
    pid_t pid;

    if (pipe(p_stdin) != 0 || pipe(p_stdout) != 0)
        return -1;

    pid = fork();

    if (pid < 0)
        return pid;
    else if (pid == 0)
    {
        close(p_stdin[WRITE]);
        dup2(p_stdin[READ], READ);
        close(p_stdout[READ]);
        dup2(p_stdout[WRITE], WRITE);

        execvp(*command, command);
        _exit(1);
    }

    if (infp == NULL)
        close(p_stdin[WRITE]);
    else
        *infp = p_stdin[WRITE];

    if (outfp == NULL)
        close(p_stdout[READ]);
    else
        *outfp = p_stdout[READ];

    return pid;
}

void switch_cgroup(const char *cgroup, int pid) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%s/cgroup.procs", cgroup);
    if (access(buf, F_OK) != 0)
        return;
    int fd = open(buf, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd == -1)
        return;
    snprintf(buf, sizeof(buf), "%d\n", pid);
    write(fd, buf, strlen(buf));
    close(fd);
}

