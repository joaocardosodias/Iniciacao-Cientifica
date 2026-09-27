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
#include <stddef.h>
#include <string.h>

static size_t discard_response(char *data, size_t size, size_t count, void *user_data)
{
    (void)data;
    (void)user_data;
    return size * count;
}

int transmit_token(const char *endpoint, const char *token_json)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode result;
    long response_code = 0;
    size_t body_length;
    int status = -1;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        return -1;

    body_length = strlen(token_json);
    curl = curl_easy_init();
    if (curl == NULL)
        return -1;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_length) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK)
        goto cleanup;

    result = curl_easy_perform(curl);
    if (result == CURLE_OK &&
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) == CURLE_OK &&
        response_code == 200)
        status = 0;

cleanup:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return status;
}