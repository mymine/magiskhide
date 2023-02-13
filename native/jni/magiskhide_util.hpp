#pragma once
#include <stdio.h>
#include <vector>
#include <map>
#define SIGTERMTHRD SIGUSR1

extern const char *MAGISKTMP;
extern std::map<int, std::string> uid_proc_map;

bool is_hide_target(int uid, const char *process, int len = 1024);
void hide_daemon(int pid);
void proc_monitor();

