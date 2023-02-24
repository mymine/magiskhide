#pragma once
#include <stdio.h>
#include <vector>
#include <map>
#define SIGTERMTHRD SIGUSR1

extern const char *MAGISKTMP;

extern std::map<int, std::vector<std::string>> uid_proc_map;

extern bool new_magic_mount;
extern bool trace_log;

bool is_hide_target(int uid, const char *process, int len = 1024);
void hide_daemon(int pid);
void hide_unmount(int pid = -1);
void proc_monitor();
bool find_proc_from_pkg(const char *pkg, const char *proc, bool start = false);

