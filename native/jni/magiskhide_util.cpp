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

#include "magiskhide_util.hpp"
#include "utils.hpp"
#include "logging.hpp"

using namespace std;

bool is_hide_target(int uid, const char *process, int len) {
    struct pstream hidels;
    char buf[4098];
    int app_id = uid % 100000;
    if (uid >= 90000) {
        snprintf(buf, sizeof(buf) - 1, "SELECT process FROM denylist WHERE package_name = 'isolated' AND process LIKE '%s", process);
        char *strchar_buf = strchr(buf, ':');
        if (strchar_buf != nullptr)
            strcpy(strchar_buf, "\%'");
        else {
            strcpy(buf + strlen(buf), "\%'");
        }
    } else {
        auto it = uid_proc_map.find(app_id);
        if (it == uid_proc_map.end())
            return false;
        if (strlen(process) > len) {
            snprintf(buf, sizeof(buf) - 1, "SELECT process FROM denylist WHERE package_name = '%s' AND process LIKE '%s\%'", it->second.data(), process);
        } else {
            snprintf(buf, sizeof(buf) - 1, "SELECT process FROM denylist WHERE package_name = '%s' AND process = '%s'", it->second.data(), process);
        }
    }
    LOGD("sqlite: %s\n", buf);
    char *magiskcmd[] = { "magisk", "--sqlite", buf, nullptr };

    if (hidels.open(magiskcmd) <= 0)
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

static void lazy_unmount(const char* mountpoint) {
    if (umount2(mountpoint, MNT_DETACH) != -1)
        LOGD("hide: Unmounted (%s)\n", mountpoint);
}

#define IS_TMPFS(s) (info.type == "tmpfs" && starts_with(info.target.data(), "/" s "/"))

static void hide_unmount(int pid) {
    if (switch_mnt_ns(pid))
        return;
    std::vector<std::string> targets;
    for (auto &info: parse_mount_info("self")) {
        if (starts_with(info.target.data(), MAGISKTMP) || // things in magisktmp
            starts_with(info.root.data(), "/adb/modules") || // module nodes
            IS_TMPFS("system") || 
            IS_TMPFS("vendor") || 
            IS_TMPFS("system_ext") || 
            IS_TMPFS("product")) { // skeleton
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

