#define _POSIX_C_SOURCE 200809L
#include "net.h"

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

int net_send_line(int fd, const char *line) {
    size_t len = 0;
    while (line[len] != '\0') len++;

    /* Include a newline delimiter; send() is allowed to write only a prefix. */
    size_t total = len + 1;
    size_t sent = 0;
    while (sent < total) {
        const char *ptr;
        size_t remaining;
        char newline = '\n';
        if (sent < len) {
            ptr = line + sent;
            remaining = len - sent;
        } else {
            ptr = &newline;
            remaining = 1;
        }
        ssize_t n = send(fd, ptr, remaining, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

int net_recv_line(int fd, char *buffer, size_t capacity) {
    if (!buffer || capacity < 2) return -1;
    size_t used = 0;
    while (used + 1 < capacity) {
        char ch;
        ssize_t n = recv(fd, &ch, 1, 0);
        if (n == 0) {
            if (used == 0) return 0;
            break;
        }
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (ch == '\n') break;
        if (ch != '\r') buffer[used++] = ch;
    }
    buffer[used] = '\0';
    return 1;
}
