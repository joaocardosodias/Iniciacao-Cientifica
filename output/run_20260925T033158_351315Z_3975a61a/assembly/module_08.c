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

static int read_file(const char *path, char **out_buf, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    size_t read = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (read != (size_t)sz) {
        free(buf);
        return -1;
    }

    buf[sz] = '\0';  
    *out_buf = buf;
    *out_len = (size_t)sz;
    return 0;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    char *data = NULL;
    size_t data_len = 0;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    long http_code = 0;
    int ret = -1;

    if (read_file(token_path, &data, &data_len) != 0)
        goto cleanup;

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0)
        goto cleanup;

    curl = curl_easy_init();
    if (!curl)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data) != CURLE_OK)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)data_len) != CURLE_OK)
        goto cleanup;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK)
        goto cleanup;

    if (curl_easy_perform(curl) != CURLE_OK)
        goto cleanup;

    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code) != CURLE_OK)
        goto cleanup;

    ret = (http_code == 200) ? 0 : -1;

cleanup:
    if (headers)
        curl_slist_free_all(headers);
    if (curl)
        curl_easy_cleanup(curl);
    curl_global_cleanup();
    if (data)
        free(data);
    return ret;
}