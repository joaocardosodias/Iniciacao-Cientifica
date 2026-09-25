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

static pthread_once_t transmit_token_curl_once = PTHREAD_ONCE_INIT;
static CURLcode transmit_token_curl_init_result = CURLE_FAILED_INIT;

static void transmit_token_curl_global_init(void)
{
    transmit_token_curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t transmit_token_discard_response(char *data, size_t size,
                                             size_t nmemb, void *userdata)
{
    (void)data;
    (void)userdata;
    return size * nmemb;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *file = NULL;
    unsigned char *body = NULL;
    size_t body_length = 0;
    size_t capacity = 0;
    unsigned char chunk[8192];
    struct curl_slist *headers = NULL;
    CURL *curl = NULL;
    CURLcode curl_result;
    curl_off_t curl_body_length;
    long http_status = 0;
    int result = -1;

    if (endpoint == NULL || token_path == NULL)
        return -1;

    file = fopen(token_path, "rb");
    if (file == NULL)
        goto done;

    for (;;) {
        size_t count = fread(chunk, 1, sizeof(chunk), file);
        if (count != 0) {
            size_t needed;
            size_t new_capacity;
            unsigned char *new_body;

            if (count > SIZE_MAX - body_length - 1)
                goto done;
            needed = body_length + count + 1;

            if (needed > capacity) {
                new_capacity = capacity != 0 ? capacity : sizeof(chunk);
                while (new_capacity < needed) {
                    if (new_capacity > SIZE_MAX / 2) {
                        new_capacity = needed;
                        break;
                    }
                    new_capacity *= 2;
                }
                new_body = realloc(body, new_capacity);
                if (new_body == NULL)
                    goto done;
                body = new_body;
                capacity = new_capacity;
            }

            for (size_t i = 0; i < count; ++i)
                body[body_length + i] = chunk[i];
            body_length += count;
        }

        if (count < sizeof(chunk)) {
            if (ferror(file))
                goto done;
            if (feof(file))
                break;
        }
    }

    if (fclose(file) != 0) {
        file = NULL;
        goto done;
    }
    file = NULL;

    if (body == NULL) {
        body = malloc(1);
        if (body == NULL)
            goto done;
    }
    body[body_length] = '\0';

    curl_body_length = (curl_off_t)body_length;
    if (curl_body_length < 0 || (size_t)curl_body_length != body_length)
        goto done;

    if (pthread_once(&transmit_token_curl_once,
                     transmit_token_curl_global_init) != 0 ||
        transmit_token_curl_init_result != CURLE_OK)
        goto done;

    curl = curl_easy_init();
    if (curl == NULL)
        goto done;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto done;

    curl_result = curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    if (curl_result != CURLE_OK)
        goto done;
    curl_result = curl_easy_setopt(curl, CURLOPT_POST, 1L);
    if (curl_result != CURLE_OK)
        goto done;
    curl_result = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (curl_result != CURLE_OK)
        goto done;
    curl_result = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    if (curl_result != CURLE_OK)
        goto done;
    curl_result = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                                   curl_body_length);
    if (curl_result != CURLE_OK)
        goto done;
    curl_result = curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (curl_result != CURLE_OK)
        goto done;
    curl_result = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                                   transmit_token_discard_response);
    if (curl_result != CURLE_OK)
        goto done;

    curl_result = curl_easy_perform(curl);
    if (curl_result != CURLE_OK)
        goto done;

    curl_result = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
    if (curl_result == CURLE_OK && http_status == 200)
        result = 0;

done:
    if (file != NULL)
        fclose(file);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    if (headers != NULL)
        curl_slist_free_all(headers);
    free(body);
    return result;
}