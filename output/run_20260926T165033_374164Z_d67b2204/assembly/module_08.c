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

static void transmit_token_initialize_curl(void)
{
    transmit_token_curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
}

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *file = NULL;
    char *body = NULL;
    size_t length = 0;
    size_t capacity = 8192;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode curl_result;
    curl_off_t body_size;
    long response_status = 0;
    int result = -1;

    if (endpoint == NULL || token_path == NULL)
        return -1;

    file = fopen(token_path, "rb");
    if (file == NULL)
        return -1;

    body = malloc(capacity);
    if (body == NULL)
        goto cleanup;

    for (;;) {
        size_t bytes_read;

        if (length == capacity) {
            size_t new_capacity;

            if (capacity > (size_t)-1 / 2)
                goto cleanup;
            new_capacity = capacity * 2;

            char *new_body = realloc(body, new_capacity);
            if (new_body == NULL)
                goto cleanup;
            body = new_body;
            capacity = new_capacity;
        }

        bytes_read = fread(body + length, 1, capacity - length, file);
        length += bytes_read;

        if (bytes_read == 0) {
            if (ferror(file))
                goto cleanup;
            break;
        }
    }

    if (fclose(file) != 0) {
        file = NULL;
        goto cleanup;
    }
    file = NULL;

    body_size = (curl_off_t)length;
    if (body_size < 0 || (size_t)body_size != length)
        goto cleanup;

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
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, body_size) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK)
        goto cleanup;

    curl_result = curl_easy_perform(curl);
    if (curl_result != CURLE_OK)
        goto cleanup;

    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_status) != CURLE_OK)
        goto cleanup;

    if (response_status == 200)
        result = 0;

cleanup:
    if (file != NULL)
        fclose(file);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    if (headers != NULL)
        curl_slist_free_all(headers);
    free(body);
    return result;
}