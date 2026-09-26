#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int write_text_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1)
        return -1;

    size_t len = strlen(text);
    ssize_t written = write(fd, text, len);
    int close_ret = close(fd);

    if (written == -1 || (size_t)written != len || close_ret == -1)
        return -1;

    return 0;
}