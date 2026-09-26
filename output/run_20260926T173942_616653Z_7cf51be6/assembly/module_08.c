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
#include <string.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    CURL *curl;
    CURLcode rc;
    long http_code = 0;
    struct curl_slist *hdrs = NULL;
    int result = -1;

    if (!endpoint || !token_json)
        return -1;

    curl = curl_easy_init();
    if (!curl)
        return -1;

    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    if (!hdrs) {
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(token_json));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) {
        if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code) == CURLE_OK) {
            if (http_code == 200)
                result = 0;
        }
    }

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return result;
}