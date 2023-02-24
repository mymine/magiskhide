#pragma once
#include <string>
#include <iostream>
#include <pthread.h>
#include <vector>
#include <sys/wait.h>
#include <string>

using thread_entry = void *(*)(void *);

long xptrace(int request, pid_t pid, void *addr = nullptr, void *data = nullptr);
static inline long xptrace(int request, pid_t pid, void *addr, uintptr_t data) {
    return xptrace(request, pid, addr, reinterpret_cast<void *>(data));
}
#define WEVENT(s) (((s) & 0xffff0000) >> 16)
int xinotify_init1(int flags);
int fork_dont_care();
int parse_int(std::string_view s);
int new_daemon_thread(thread_entry entry, void *arg);
int new_daemon_thread(void(*entry)());
int switch_mnt_ns(int pid);
	
struct mount_info {
    unsigned int id;
    unsigned int parent;
    dev_t device;
    std::string root;
    std::string target;
    std::string vfs_option;
    struct {
        unsigned int shared;
        unsigned int master;
        unsigned int propagate_from;
    } optional;
    std::string type;
    std::string source;
    std::string fs_option;
};

std::vector<mount_info> parse_mount_info(const char *pid);

void set_nice_name(int argc, char **argv, const char *name);
#define set_nice_name(s) set_nice_name(argc,argv,s)

bool starts_with(const char *s, const char *ss);

pid_t popen2(char **command, int *infp, int *outfp);

struct pstream {
    pid_t pid;
    int in,out;
    int open(char **command){
        return pid = popen2(command,&in,&out);
    }
    void term(){
        if (pid >= 0){
            kill(pid, SIGKILL);
            waitpid(pid,0,0);
            pid = -1;
        }
        close(in);
        close(out);
        in = -1;
        out = -1;
    }
    void close_pipe(){
        close(in);
        close(out);
        in = -1;
        out = -1;
    }
    void init(){
        pid= -1;
        in= -1;
        out= -1;
    }
};

void switch_cgroup(const char *cgroup, int pid);
int parse_ppid(int pid);

template <typename T>
class reversed_container {
public:
    reversed_container(T &base) : base(base) {}
    decltype(std::declval<T>().rbegin()) begin() { return base.rbegin(); }
    decltype(std::declval<T>().crbegin()) begin() const { return base.crbegin(); }
    decltype(std::declval<T>().crbegin()) cbegin() const { return base.crbegin(); }
    decltype(std::declval<T>().rend()) end() { return base.rend(); }
    decltype(std::declval<T>().crend()) end() const { return base.crend(); }
    decltype(std::declval<T>().crend()) cend() const { return base.crend(); }
private:
    T &base;
};

template <typename T>
reversed_container<T> reversed(T &base) {
    return reversed_container<T>(base);
}

