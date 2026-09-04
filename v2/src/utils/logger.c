#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include "libp2p/utils/logger.h"

static void log_message(const char* level, const char* subsystem, const char* format, va_list args) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("[%s] [%s] [%s]: ", timestamp, level, subsystem);
    vprintf(format, args);
    printf("\n");
}

void libp2p_logger_info(const char* subsystem, const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message("INFO", subsystem, format, args);
    va_end(args);
}

void libp2p_logger_error(const char* subsystem, const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message("ERROR", subsystem, format, args);
    va_end(args);
}

void libp2p_logger_debug(const char* subsystem, const char* format, ...) {
    va_list args;
    va_start(args, format);
    log_message("DEBUG", subsystem, format, args);
    va_end(args);
}
