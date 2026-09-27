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
#include <stddef.h>

static pthread_once_t curl_once = PTHREAD_ONCE_INIT;
static CURLcode curl_init_result = CURLE_FAILED_INIT;

static void initialize_curl(void)
{
    curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t discard_response(char *data, size_t size, size_t nmemb, void *userdata)
{
    (void)data;
    (void)userdata;
    return size * nmemb;
}

int transmit_token(const char *endpoint, const char *token_json)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode result;
    long status = 0;
    int rc = -1;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    if (pthread_once(&curl_once, initialize_curl) != 0 ||
        curl_init_result != CURLE_OK)
        return -1;

    curl = curl_easy_init();
    if (curl == NULL)
        return -1;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto done;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK)
        goto done;

    result = curl_easy_perform(curl);
    if (result != CURLE_OK ||
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK ||
        status != 200)
        goto done;

    rc = 0;

done:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return rc;
}