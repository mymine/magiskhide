#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <vector>
#include <bitset>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <dirent.h>
#include <map>
#include <dirent.h>

#include "utils.hpp"
#include "magiskhide_util.hpp"
#include "logging.hpp"

using namespace std;

static int inotify_fd = -1;

static void new_zygote(int pid);

std::map<int, std::vector<std::string>> uid_proc_map;

pthread_t monitor_thread;

static int fork_pid = -1;

#include "procfp.hpp"

/******************
 * Data structures
 ******************/

#define PID_MAX 32768
struct pid_set {
    bitset<PID_MAX>::const_reference operator[](size_t pos) const { return set[pos - 1]; }
    bitset<PID_MAX>::reference operator[](size_t pos) { return set[pos - 1]; }
    void reset() { set.reset(); }
private:
    bitset<PID_MAX> set;
};

// true if pid is monitored
static pid_set attaches;

// zygote pid -> mnt ns
static map<int, struct stat> zygote_map;

// handle list
static vector<int> pid_list;

/********
 * Utils
 ********/
 
static void update_uid_map() {
    const char *APP_DATA = "/data/user_de/0";
    DIR *dirfp = opendir(APP_DATA);
    if (dirfp == nullptr) {
        APP_DATA = "/data/data";
        dirfp = opendir(APP_DATA);
    }
    if (dirfp == nullptr)
        return;
    LOGI("hide: rescanning apps\n");
    struct dirent *dp;
    struct stat st;
    char buf[4098];
    while ((dp = readdir(dirfp)) != nullptr) {
        snprintf(buf, sizeof(buf) - 1, "%s/%s", APP_DATA, dp->d_name);
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0 ||
            stat(buf, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;

        auto it = uid_proc_map.find(st.st_uid);
        if (it == uid_proc_map.end()) {
            std::vector<std::string> init;
            init.emplace_back(std::string(dp->d_name));
            uid_proc_map[st.st_uid] = init;
            LOGD("proc_monitor: add map uid=[%d] [%s]\n", st.st_uid, dp->d_name);
        } else {
            bool found = false;
            for (int i = 0; i < it->second.size(); i++) {
                if (it->second[i] == std::string(dp->d_name)) {
                    found = true;
                    break;
                }
            }
            if (!found) { 
                it->second.emplace_back(std::string(dp->d_name));
                LOGD("proc_monitor: update map uid=[%d] [%s]\n", st.st_uid, dp->d_name);
            }
        }
    }
    closedir(dirfp);    
}

static inline int read_ns(const int pid, struct stat *st) {
    char path[32];
    sprintf(path, "/proc/%d/ns/mnt", pid);
    return stat(path, st);
}

static int parse_ppid(int pid) {
    char path[32];
    int ppid;

    sprintf(path, "/proc/%d/stat", pid);

    auto stat = fopen(path, "re");
    if (!stat)
        return -1;

    // PID COMM STATE PPID .....
    fscanf(stat, "%*d %*s %*c %d", &ppid);
    fclose(stat);
    return ppid;
}

static bool is_zygote_done() {
    return zygote_map.size() >= 1;
}

static void check_zygote() {
    crawl_procfs([](int pid) -> bool {
        char buf[512];
        snprintf(buf, sizeof(buf), "/proc/%d/attr/current", pid);
        if (FILE *f = fopen(buf, "re")) {
            fgets(buf, sizeof(buf), f);
            if (buf == "u:r:zygote:s0"sv && parse_ppid(pid) == 1)
                new_zygote(pid);
            fclose(f);
        }
        return true;
    });
    if (is_zygote_done()) {
        // Stop periodic scanning
        timeval val { .tv_sec = 0, .tv_usec = 0 };
        itimerval interval { .it_interval = val, .it_value = val };
        setitimer(ITIMER_REAL, &interval, nullptr);
    }
}

#define APP_PROC "/system/bin/app_process"

static void setup_inotify() {
    inotify_fd = xinotify_init1(IN_CLOEXEC);
    if (inotify_fd < 0)
        return;

    // Setup inotify asynchronous I/O
    fcntl(inotify_fd, F_SETFL, O_ASYNC);
    struct f_owner_ex ex = {
        .type = F_OWNER_TID,
        .pid = gettid()
    };
    fcntl(inotify_fd, F_SETOWN_EX, &ex);

    // Monitor packages.xml
    inotify_add_watch(inotify_fd, "/data/system", IN_CLOSE_WRITE);

    // Monitor app_process
    if (access(APP_PROC "32", F_OK) == 0) {
        inotify_add_watch(inotify_fd, APP_PROC "32", IN_ACCESS);
        if (access(APP_PROC "64", F_OK) == 0)
            inotify_add_watch(inotify_fd, APP_PROC "64", IN_ACCESS);
    } else {
        inotify_add_watch(inotify_fd, APP_PROC, IN_ACCESS);
    }
}

/************************
 * Async signal handlers
 ************************/

static void inotify_event(int) {
    // Make sure we can actually read stuffs
    // or else the whole thread will be blocked.
    struct pollfd pfd = {
        .fd = inotify_fd,
        .events = POLLIN,
        .revents = 0
    };
    if (poll(&pfd, 1, 0) <= 0)
        return;  // Nothing to read
    char buf[512];
    auto event = reinterpret_cast<struct inotify_event *>(buf);
    read(inotify_fd, buf, sizeof(buf));
    if ((event->mask & IN_CLOSE_WRITE) && strcmp(event->name, "packages.xml") == 0) {
        new_daemon_thread(&update_uid_map);
    } else if (event->mask & IN_ACCESS) {
        check_zygote();
    }
}

static void term_thread(int) {
    LOGD("proc_monitor: cleaning up\n");
    zygote_map.clear();
    attaches.reset();
    close(inotify_fd);
    inotify_fd = -1;
    fork_pid = -1;
    for (int i = 0; i < pid_list.size(); i++) {
        LOGD("proc_monitor: kill PID=[%d]\n", pid_list[i]);
        kill(pid_list[i], SIGKILL);
    }
    pid_list.clear();
    // Restore all signal handlers that was set
    sigset_t set;
    sigfillset(&set);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);
    struct sigaction act{};
    act.sa_handler = SIG_DFL;
    sigaction(SIGTERMTHRD, &act, nullptr);
    sigaction(SIGIO, &act, nullptr);
    sigaction(SIGALRM, &act, nullptr);
    LOGD("proc_monitor: terminate\n");
    pthread_exit(nullptr);
}

/******************
 * Ptrace Madness
 ******************/

// Ptrace is super tricky, preserve all excessive logging in code
// but disable when actually building for usage (you won't want
// your logcat spammed with new thread events from all apps)

//#define PTRACE_LOG(fmt, args...) LOGD("PID=[%d] " fmt, pid, ##args)
#define PTRACE_LOG(...)

static void detach_pid(int pid, int signal = 0) {
    attaches[pid] = false;
    ptrace(PTRACE_DETACH, pid, 0, signal);
    PTRACE_LOG("detach\n");
}

static bool check_pid(int pid) {
    char path[128];
    char cmdline[1024];
    struct stat st;

    sprintf(path, "/proc/%d", pid);
    if (stat(path, &st)) {
        // Process died unexpectedly, ignore
        detach_pid(pid);
        return true;
    }

    int uid = st.st_uid;

    // UID hasn't changed
    if (uid == 0)
        return false;

    sprintf(path, "/proc/%d/cmdline", pid);
    if (auto f = fopen(path, "re")) {
        fgets(cmdline, sizeof(cmdline), f);
        fclose(f);
    } else {
        // Process died unexpectedly, ignore
        detach_pid(pid);
        return true;
    }

    if (cmdline == "zygote"sv || cmdline == "zygote32"sv || cmdline == "zygote64"sv ||
        cmdline == "usap32"sv || cmdline == "usap64"sv || cmdline == "<pre-initialized>"sv)
        return false;

    if (!is_hide_target(uid, cmdline, 95))
        goto not_target;

    // Ensure ns is separated
    read_ns(pid, &st);
    for (auto &zit : zygote_map) {
        if (zit.second.st_ino == st.st_ino &&
            zit.second.st_dev == st.st_dev) {
            // ns not separated, abort
            LOGW("proc_monitor: skip [%s] PID=[%d] UID=[%d]\n", cmdline, pid, uid);
            goto not_target;
        }
    }

    // Detach but the process should still remain stopped
    // The hide daemon will resume the process after hiding it
    LOGI("proc_monitor: [%s] PID=[%d] UID=[%d]\n", cmdline, pid, uid);
    detach_pid(pid);
    kill(pid, SIGSTOP);
    hide_daemon(pid);
    return true;

not_target:
    PTRACE_LOG("[%s] is not our target\n", cmdline);
    detach_pid(pid);
    return true;
}

static bool is_process(int pid) {
    char buf[128];
    char key[32];
    int tgid;
    sprintf(buf, "/proc/%d/status", pid);
    auto fp = fopen(buf, "re");
    // PID is dead
    if (!fp)
        return false;
    while (fgets(buf, sizeof(buf), fp)) {
        sscanf(buf, "%s", key);
        if (key == "Tgid:"sv) {
            sscanf(buf, "%*s %d", &tgid);
            fclose(fp);
            return tgid == pid;
        }
    }
    fclose(fp);
    return false;
}

static void new_zygote(int pid) {
    struct stat st;
    if (read_ns(pid, &st))
        return;

    auto it = zygote_map.find(pid);
    if (it != zygote_map.end()) {
        // Update namespace info
        it->second = st;
        return;
    }

    LOGD("proc_monitor: ptrace zygote PID=[%d]\n", pid);
    zygote_map[pid] = st;

    xptrace(PTRACE_ATTACH, pid);

    waitpid(pid, nullptr, __WALL | __WNOTHREAD);
    xptrace(PTRACE_SETOPTIONS, pid, nullptr,
            PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXIT);
    xptrace(PTRACE_CONT, pid);
}

#define DETACH_AND_CONT { detach_pid(pid); continue; }

int wait_for_syscall(pid_t pid) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        PTRACE_LOG("wait for syscall\n");
        int child = waitpid(pid, &status, 0);
        if (child < 0)
            return 1;
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
            PTRACE_LOG("make a syscall\n");
            return 0;
        }
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV) {
            // google chrome?
            PTRACE_LOG("SIGSEGV from child\n");
            return 1;
        }
        if (WIFEXITED(status)) {
            PTRACE_LOG("exited\n");
            return 1;
        }
    }
}

inline int read_syscall_num(int pid) {
    int sys = -1;
    char buf[1024];
    sprintf(buf, "/proc/%d/syscall", pid);
    FILE *fp = fopen(buf, "re");
    if (fp) {
        fscanf(fp, "%d", &sys);
        fclose(fp);
    }
    return sys;
}

static std::string get_content(int pid, const char *file) {
    char buf[1024];
    sprintf(buf, "/proc/%d/%s", pid, file);
    FILE *fp = fopen(buf, "re");
    if (fp) {
        fgets(buf, sizeof(buf), fp);
        fclose(fp);
        return std::string(buf);
    }
    return std::string("");
}

void do_check_fork() {
    int pid = fork_pid;
    fork_pid = 0;
    if (pid <= 0)
        return;
    // wait until thread detach this pid
    for (int i = 0; i < 10000 && ptrace(PTRACE_ATTACH, pid) < 0; i++)
        usleep(100);
    PTRACE_LOG("pass to thread\n");
    bool allow = false;
    bool checked = false;
    pid_list.emplace_back(pid);
    waitpid(pid, 0, 0);
    xptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACESYSGOOD);
    struct stat st{};
    char path[128];
    for (int syscall_num = -1;;) {
        if (wait_for_syscall(pid) != 0)
            break;
        syscall_num = read_syscall_num(pid);
        if (syscall_num == __NR_prctl) {
            if (checked) goto CHECK_PROC;
            sprintf(path, "/proc/%d", pid);
            stat(path, &st);
            PTRACE_LOG("UID=[%d]\n", st.st_uid);
            if (st.st_uid == 0)
                continue;
            if ((st.st_uid % 100000) >= 90000) {
                PTRACE_LOG("is isolated process\n");
                goto CHECK_PROC;
            }
            // check if UID is on list
            {
                bool found = false;
                auto it = uid_proc_map.find(st.st_uid % 100000);
                // not found in map
                if (it == uid_proc_map.end())
                    break;
                for (int i = 0; i < it->second.size(); i++) {
                    if (find_proc_from_pkg(it->second[i].data(), it->second[i].data(), true)) {
                        found = true;
                        break;
                    }
                }
                // not found in database
                if (!found) break;
            }

            CHECK_PROC:
            checked = true;
            if (!allow && (
                 // app zygote
                 strstr(get_content(pid, "attr/current").data(), "u:r:app_zygote:s0") ||
                 // until pre-initialized
                 get_content(pid, "cmdline") == "<pre-initialized>"))
                 allow = true;
            if (allow && check_pid(pid))
                break;
        }
    }
    // just in case
    PTRACE_LOG("detach\n");
    ptrace(PTRACE_DETACH, pid);
    auto it = find(pid_list.begin(), pid_list.end(), pid);
    if (it != pid_list.end())
        pid_list.erase(it);
}

void proc_monitor() {
    monitor_thread = pthread_self();

    // Backup original mask
    sigset_t orig_mask;
    pthread_sigmask(SIG_SETMASK, nullptr, &orig_mask);

    sigset_t unblock_set;
    sigemptyset(&unblock_set);
    sigaddset(&unblock_set, SIGTERMTHRD);
    sigaddset(&unblock_set, SIGIO);
    sigaddset(&unblock_set, SIGALRM);

    struct sigaction act{};
    sigfillset(&act.sa_mask);
    act.sa_handler = SIG_IGN;
    sigaction(SIGTERMTHRD, &act, nullptr);
    sigaction(SIGIO, &act, nullptr);
    sigaction(SIGALRM, &act, nullptr);

    // Temporary unblock to clear pending signals
    pthread_sigmask(SIG_UNBLOCK, &unblock_set, nullptr);
    pthread_sigmask(SIG_SETMASK, &orig_mask, nullptr);

    act.sa_handler = term_thread;
    sigaction(SIGTERMTHRD, &act, nullptr);
    act.sa_handler = inotify_event;
    sigaction(SIGIO, &act, nullptr);
    act.sa_handler = [](int){ check_zygote(); };
    sigaction(SIGALRM, &act, nullptr);

    setup_inotify();

    // First try find existing zygotes
    check_zygote();
    update_uid_map();
    if (!is_zygote_done()) {
        // Periodic scan every 250ms
        timeval val { .tv_sec = 0, .tv_usec = 250000 };
        itimerval interval { .it_interval = val, .it_value = val };
        setitimer(ITIMER_REAL, &interval, nullptr);
    }

    for (int status;;) {
        pthread_sigmask(SIG_UNBLOCK, &unblock_set, nullptr);

        const int pid = waitpid(-1, &status, __WALL | __WNOTHREAD);
        if (pid < 0) {
            if (errno == ECHILD) {
                // Nothing to wait yet, sleep and wait till signal interruption
                LOGD("proc_monitor: nothing to monitor, wait for signal\n");
                struct timespec ts = {
                    .tv_sec = INT_MAX,
                    .tv_nsec = 0
                };
                nanosleep(&ts, nullptr);
            }
            continue;
        }

        pthread_sigmask(SIG_SETMASK, &orig_mask, nullptr);

        if (!WIFSTOPPED(status) /* Ignore if not ptrace-stop */)
            DETACH_AND_CONT;

        int event = WEVENT(status);
        int signal = WSTOPSIG(status);

        if (signal == SIGTRAP && event) {
            unsigned long msg;
            xptrace(PTRACE_GETEVENTMSG, pid, nullptr, &msg);
            if (zygote_map.count(pid)) {
                // Zygote event
                switch (event) {
                    case PTRACE_EVENT_FORK:
                    case PTRACE_EVENT_VFORK:
                        PTRACE_LOG("zygote forked: [%lu]\n", msg);
                        attaches[msg] = true;
                        break;
                    case PTRACE_EVENT_EXIT:
                        PTRACE_LOG("zygote exited with status: [%lu]\n", msg);
                        [[fallthrough]];
                    default:
                        zygote_map.erase(pid);
                        DETACH_AND_CONT;
                }
            } else {
                DETACH_AND_CONT;
            }
            xptrace(PTRACE_CONT, pid);
        } else if (signal == SIGSTOP) {
            if (!attaches[pid]) {
                // Double check if this is actually a process
                attaches[pid] = is_process(pid);
            }
            if (attaches[pid]) {
                // This is a process, continue monitoring
                attaches[pid] = false;
                detach_pid(pid);
                fork_pid = pid;
                new_daemon_thread(&do_check_fork);
            } else {
                // This is a thread, do NOT monitor
                PTRACE_LOG("SIGSTOP from thread\n");
                DETACH_AND_CONT;
            }
        } else {
            // Not caused by us, resend signal
            xptrace(PTRACE_CONT, pid, nullptr, signal);
            PTRACE_LOG("signal [%d]\n", signal);
        }
    }
}
