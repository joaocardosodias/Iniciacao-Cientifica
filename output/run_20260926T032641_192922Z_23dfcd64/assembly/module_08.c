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
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_once_t transmit_token_curl_once = PTHREAD_ONCE_INIT;
static CURLcode transmit_token_curl_init_result = CURLE_FAILED_INIT;

static void transmit_token_initialize_curl(void)
{
    transmit_token_curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t transmit_token_discard_response(char *data, size_t size,
                                               size_t nmemb, void *userdata)
{
    (void)data;
    (void)userdata;
    if (size != 0 && nmemb > SIZE_MAX / size)
        return 0;
    return size * nmemb;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *file = NULL;
    unsigned char *body = NULL;
    size_t body_len = 0;
    size_t body_capacity = 0;
    unsigned char chunk[8192];
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode result;
    long http_status = 0;
    int status = -1;

    if (endpoint == NULL || token_path == NULL)
        return -1;

    file = fopen(token_path, "rb");
    if (file == NULL)
        goto cleanup;

    for (;;) {
        size_t count = fread(chunk, 1, sizeof(chunk), file);
        if (count != 0) {
            size_t needed;
            size_t new_capacity;
            unsigned char *new_body;

            if (body_len > SIZE_MAX - count - 1)
                goto cleanup;
            needed = body_len + count + 1;

            if (needed > body_capacity) {
                new_capacity = body_capacity ? body_capacity : sizeof(chunk);
                while (new_capacity < needed) {
                    if (new_capacity > SIZE_MAX / 2) {
                        new_capacity = needed;
                        break;
                    }
                    new_capacity *= 2;
                }
                new_body = realloc(body, new_capacity);
                if (new_body == NULL)
                    goto cleanup;
                body = new_body;
                body_capacity = new_capacity;
            }

            memcpy(body + body_len, chunk, count);
            body_len += count;
        }

        if (count < sizeof(chunk)) {
            if (ferror(file))
                goto cleanup;
            if (feof(file))
                break;
        }
    }

    if (fclose(file) != 0) {
        file = NULL;
        goto cleanup;
    }
    file = NULL;

    if (body == NULL) {
        body = malloc(1);
        if (body == NULL)
            goto cleanup;
    }
    body[body_len] = '\0';

    if (pthread_once(&transmit_token_curl_once, transmit_token_initialize_curl) != 0 ||
        transmit_token_curl_init_result != CURLE_OK)
        goto cleanup;

    curl = curl_easy_init();
    if (curl == NULL)
        goto cleanup;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)body) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t)body_len) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                         transmit_token_discard_response) != CURLE_OK)
        goto cleanup;

    result = curl_easy_perform(curl);
    if (result != CURLE_OK)
        goto cleanup;

    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status) != CURLE_OK)
        goto cleanup;

    if (http_status == 200)
        status = 0;

cleanup:
    if (file != NULL)
        fclose(file);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    if (headers != NULL)
        curl_slist_free_all(headers);
    free(body);
    return status;
}