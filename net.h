#ifndef NET_H
#define NET_H
#include <stddef.h>

/* Newline-delimited messages over TCP. Returns 1, 0 on EOF, or -1 on error. */
int net_send_line(int fd, const char *line);
int net_recv_line(int fd, char *buffer, size_t capacity);

#endif
