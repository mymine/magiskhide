#include <iostream>
#include <stdio.h>
#include <ctime>
#include <chrono>
#include <unistd.h>
#include <android/log.h>

using namespace std;

void log_to_file(int fd, int prio, const char *log) {
    if (fd < 0) {
        printf("%s", log);
        return;
    }
    char prio_c = 'I';
    switch (prio) {
        case ANDROID_LOG_DEBUG:
            prio_c = 'D';
            break;
        case ANDROID_LOG_WARN:
            prio_c = 'W';
            break;
        case ANDROID_LOG_VERBOSE:
            prio_c = 'V';
            break;
        case ANDROID_LOG_ERROR:
            prio_c = 'E';
            break;
        case ANDROID_LOG_FATAL:
            prio_c = 'F';
            break;
        default:
            prio_c = 'I';
            break;
    }
    char buf[4098];
    // current date/time based on current system
    time_t now = time(0);
    tm *ltm = localtime(&now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() - std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()*1000;

#define ZERO(i) if (buf[i] == ' ') buf[i] = '0';
    // print various components of tm structure.
    snprintf(buf, sizeof(buf) - 1, "%2d-%2d %2d:%2d:%2d.%3d %5d %5d %c : %s", ltm->tm_mon + 1, ltm->tm_mday, ltm->tm_hour, ltm->tm_min, ltm->tm_sec, ms, getpid(), gettid(), prio_c, log);
    ZERO(0); ZERO(3); ZERO(6); ZERO(9); ZERO(12);
    ZERO(15); ZERO(16);
#undef ZERO
    write(fd, buf, strlen(buf));
}
