#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

static size_t discard_response(char *data, size_t size, size_t count, void *userdata)
{
    (void)data;
    (void)userdata;
    if (size != 0 && count > SIZE_MAX / size)
        return 0;
    return size * count;
}

static int read_token_file(const char *path, char **contents, size_t *length)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    char *buffer = NULL;
    size_t used = 0;
    size_t capacity = 0;
    char chunk[16384];
    int result = -1;

    for (;;) {
        ssize_t n = read(fd, chunk, sizeof(chunk));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }
        if (n == 0)
            break;

        size_t amount = (size_t)n;
        if (used > SIZE_MAX - amount)
            goto done;
        size_t needed = used + amount;

        if (needed > capacity) {
            size_t new_capacity = capacity ? capacity : sizeof(chunk);
            while (new_capacity < needed) {
                if (new_capacity > SIZE_MAX / 2) {
                    new_capacity = needed;
                    break;
                }
                new_capacity *= 2;
            }
            char *new_buffer = realloc(buffer, new_capacity);
            if (new_buffer == NULL)
                goto done;
            buffer = new_buffer;
            capacity = new_capacity;
        }

        for (size_t i = 0; i < amount; ++i)
            buffer[used + i] = chunk[i];
        used = needed;
    }

    if (used == SIZE_MAX)
        goto done;
    char *new_buffer = realloc(buffer, used + 1);
    if (new_buffer == NULL)
        goto done;
    buffer = new_buffer;
    buffer[used] = '\0';

    if (close(fd) != 0) {
        fd = -1;
        goto done;
    }
    fd = -1;

    *contents = buffer;
    *length = used;
    buffer = NULL;
    result = 0;

done:
    if (fd >= 0)
        close(fd);
    free(buffer);
    return result;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    if (endpoint == NULL || token_path == NULL)
        return -1;

    char *body = NULL;
    size_t body_length = 0;
    if (read_token_file(token_path, &body, &body_length) != 0)
        return -1;

    if (body_length > (size_t)LLONG_MAX) {
        free(body);
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        free(body);
        return -1;
    }

    struct curl_slist *headers = NULL;
    struct curl_slist *new_headers =
        curl_slist_append(headers, "Content-Type: application/json");
    if (new_headers == NULL) {
        curl_easy_cleanup(curl);
        free(body);
        return -1;
    }
    headers = new_headers;

    CURLcode code = CURLE_OK;
    code = curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    if (code == CURLE_OK)
        code = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (code == CURLE_OK)
        code = curl_easy_setopt(curl, CURLOPT_POST, 1L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    if (code == CURLE_OK)
        code = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                                (curl_off_t)body_length);
    if (code == CURLE_OK)
        code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response);

    long status = 0;
    if (code == CURLE_OK)
        code = curl_easy_perform(curl);
    if (code == CURLE_OK)
        code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(body);

    return code == CURLE_OK && status == 200 ? 0 : -1;
}