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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

int transmit_token(const char *endpoint, const char *token_path) {
    FILE *fp = NULL;
    char *data = NULL;
    long file_size;
    size_t read_size;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    long response_code = 0;
    int ret = -1;

    if (!endpoint || !token_path) {
        return -1;
    }

    fp = fopen(token_path, "rb");
    if (!fp) {
        goto cleanup;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        goto cleanup;
    }
    file_size = ftell(fp);
    if (file_size < 0) {
        goto cleanup;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        goto cleanup;
    }
    data = malloc((size_t)file_size + 1);
    if (!data) {
        goto cleanup;
    }
    read_size = fread(data, 1, (size_t)file_size, fp);
    if (read_size != (size_t)file_size) {
        goto cleanup;
    }
    data[read_size] = '\0';
    size_t payload_len = strcspn(data, "\0");

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        goto cleanup;
    }

    curl = curl_easy_init();
    if (!curl) {
        goto cleanup;
    }

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        goto cleanup;
    }

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)payload_len);

    if (curl_easy_perform(curl) != CURLE_OK) {
        goto cleanup;
    }
    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) != CURLE_OK) {
        goto cleanup;
    }
    if (response_code == 200) {
        ret = 0;
    }

cleanup:
    if (headers) curl_slist_free_all(headers);
    if (curl) curl_easy_cleanup(curl);
    if (data) free(data);
    if (fp) fclose(fp);
    curl_global_cleanup();
    return ret;
}