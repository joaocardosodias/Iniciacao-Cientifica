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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static size_t discard_response(void *data, size_t size, size_t nmemb, void *context)
{
    (void)data;
    (void)context;
    return size * nmemb;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *file = NULL;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    char *body = NULL;
    size_t capacity = 8192;
    size_t length = 0;
    long status = 0;
    int result = -1;

    if (endpoint == NULL || token_path == NULL)
        return -1;

    file = fopen(token_path, "rb");
    if (file == NULL)
        goto cleanup;

    body = malloc(capacity);
    if (body == NULL)
        goto cleanup;

    for (;;) {
        size_t count = fread(body + length, 1, capacity - length - 1, file);
        length += count;

        if (ferror(file))
            goto cleanup;
        if (feof(file))
            break;

        if (length == capacity - 1) {
            char *larger;

            if (capacity > SIZE_MAX / 2)
                goto cleanup;
            capacity *= 2;
            larger = realloc(body, capacity);
            if (larger == NULL)
                goto cleanup;
            body = larger;
        }
    }

    body[length] = '\0';

    if (fclose(file) != 0) {
        file = NULL;
        goto cleanup;
    }
    file = NULL;

    curl = curl_easy_init();
    if (curl == NULL)
        goto cleanup;

    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t)length) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                         discard_response) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK)
        goto cleanup;

    if (curl_easy_perform(curl) == CURLE_OK &&
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK &&
        status == 200)
        result = 0;

cleanup:
    curl_slist_free_all(headers);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    if (file != NULL)
        fclose(file);
    free(body);
    return result;
}