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
#include <stdio.h>
#include <stdlib.h>

static size_t discard_response(char *data, size_t size, size_t count, void *userdata)
{
    (void)data;
    (void)userdata;
    return size * count;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *file;
    char *body;
    size_t length = 0;
    size_t capacity = 4096;
    struct curl_slist *headers = NULL;
    CURL *curl = NULL;
    CURLcode result;
    long status = 0;
    int rc = -1;

    if (endpoint == NULL || token_path == NULL)
        return -1;

    file = fopen(token_path, "rb");
    if (file == NULL)
        return -1;

    body = malloc(capacity);
    if (body == NULL) {
        fclose(file);
        return -1;
    }

    for (;;) {
        size_t available;
        size_t n;

        if (length >= capacity - 1) {
            size_t new_capacity = capacity * 2;
            char *new_body = realloc(body, new_capacity);

            if (new_body == NULL)
                goto cleanup_file;
            body = new_body;
            capacity = new_capacity;
        }

        available = capacity - length - 1;
        n = fread(body + length, 1, available, file);
        length += n;

        if (n < available) {
            if (ferror(file))
                goto cleanup_file;
            if (feof(file))
                break;
        }
    }

    body[length] = '\0';
    if (fclose(file) != 0) {
        free(body);
        return -1;
    }
    file = NULL;

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        goto cleanup;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;

    curl = curl_easy_init();
    if (curl == NULL)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t)length) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK)
        goto cleanup;

    result = curl_easy_perform(curl);
    if (result == CURLE_OK &&
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK &&
        status == 200)
        rc = 0;

cleanup:
    if (curl != NULL)
        curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free(body);
    return rc;

cleanup_file:
    fclose(file);
    free(body);
    return -1;
}