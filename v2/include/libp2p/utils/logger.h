#ifndef LIBP2P_UTILS_LOGGER_H
#define LIBP2P_UTILS_LOGGER_H

void libp2p_logger_info(const char* subsystem, const char* format, ...);
void libp2p_logger_error(const char* subsystem, const char* format, ...);
void libp2p_logger_debug(const char* subsystem, const char* format, ...);

#endif /* LIBP2P_UTILS_LOGGER_H */
