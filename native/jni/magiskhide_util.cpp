#include <signal.h>
#include <unistd.h>
#include <vector>
#include <sys/mount.h>
#include <iostream>
#include <iostream>
#include <string_view>
#include <string>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <algorithm>

#include "magiskhide_util.hpp"
#include "utils.hpp"
#include "logging.hpp"

using namespace std;

// true if found
bool find_proc_from_pkg(const char *pkg, const char *proc, bool start) {
    char buf[4098];
    struct pstream hidels;

    snprintf(buf, sizeof(buf) - 1, "SELECT process FROM denylist WHERE package_name = '%s' AND process %s '%s", pkg, start? "LIKE" : "=", proc);
    strcpy(buf + strlen(buf), start? "\%'" : "'");

    //LOGD("sqlite: %s\n", buf);
    
    char *magiskcmd[] = { strdup("magisk"), strdup("--sqlite"), buf, nullptr };
    int pid = hidels.open(magiskcmd);

    free(magiskcmd[0]);
    free(magiskcmd[1]);
 
    if (pid <= 0)
        return false;

    int status;
    struct pollfd pfd = {
        .fd = hidels.out,
        .events = POLLIN,
        .revents = 0
    };

    waitpid(hidels.pid, &status, 0);
    if (status > 0)
        goto is_not_target;
    if (poll(&pfd, 1, 0) > 0) {
        goto is_target;
    }

    is_not_target:
    hidels.close_pipe();
    return false;
    
    is_target:
    hidels.close_pipe();
    return true;
}

bool is_hide_target(int uid, const char *process, int len) {
    int app_id = uid % 100000;
    if (uid >= 90000) {
        char buf[4098];
        strcpy(buf, process);
        char *strchar_buf = strchr(buf, ':');
        if (strchar_buf != nullptr)
            strcpy(strchar_buf, "");
        if (find_proc_from_pkg("isolated", buf, true))
            return true;
    } else {
        auto it = uid_proc_map.find(app_id);
        if (it == uid_proc_map.end())
            return false;
        for (int i = 0; i < it->second.size(); i++) {
            if (find_proc_from_pkg(it->second[i].data(), process, strlen(process) >= len))
                return true;
        }
    }
    return false;
}

static void lazy_unmount(const char* mountpoint) {
    if (umount2(mountpoint, MNT_DETACH) != -1)
        LOGD("hide_daemon: Unmounted (%s)\n", mountpoint);
}

#define IS_TMPFS(s) (info.type == "tmpfs" && starts_with(info.target.data(), "/" s "/"))

static inline bool is_magic_tmpfs(mount_info info) {
    if (new_magic_mount) {
        return starts_with(info.root.data(), "/.magisk/");
    }
    return IS_TMPFS("system") || 
            IS_TMPFS("vendor") || 
            IS_TMPFS("system_ext") || 
            IS_TMPFS("product");
}

void hide_unmount(int pid) {
    if (pid > 0) {
        if (switch_mnt_ns(pid))
            return;
        LOGD("magiskhide: handling PID=[%d]\n", pid);
    }
    std::vector<std::string> targets;
    struct stat st;
    for (auto &info: parse_mount_info("self")) {
        if ((starts_with(info.target.data(), MAGISKTMP) || // things in magisktmp
            is_magic_tmpfs(info)) && // skeleton
            stat(info.target.data(), &st) == 0 && st.st_dev == info.device) {
            targets.push_back(info.target);
        }
    }

    for (auto &s : targets)
        lazy_unmount(s.data());

    targets.clear();

    for (auto &info: parse_mount_info("self")) {
        if (starts_with(info.root.data(), "/adb/modules") && // skeleton
            stat(info.target.data(), &st) == 0 && st.st_dev == info.device) {
            targets.push_back(info.target);
        }
    }

    for (auto &s : targets)
        lazy_unmount(s.data());
}

void hide_daemon(int pid) {
    if (fork_dont_care() == 0) {
        hide_unmount(pid);
        kill(pid, SIGCONT);
        _exit(0);
    }
}

