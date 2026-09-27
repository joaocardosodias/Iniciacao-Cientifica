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

static size_t discard_response(char *data, size_t size, size_t count, void *userdata)
{
    (void)data;
    (void)userdata;
    return size * count;
}

int transmit_token(const char *endpoint, const char *token_json)
{
    if (endpoint == NULL || token_json == NULL)
        return -1;

    CURL *curl = curl_easy_init();
    if (curl == NULL)
        return -1;

    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL) {
        curl_easy_cleanup(curl);
        return -1;
    }

    CURLcode result = curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    if (result == CURLE_OK)
        result = curl_easy_setopt(curl, CURLOPT_POST, 1L);
    if (result == CURLE_OK)
        result = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json);
    if (result == CURLE_OK)
        result = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (result == CURLE_OK)
        result = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response);

    long status = 0;
    if (result == CURLE_OK)
        result = curl_easy_perform(curl);
    if (result == CURLE_OK)
        result = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return result == CURLE_OK && status == 200 ? 0 : -1;
}