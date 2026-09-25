#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <ftw.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define ERR_DIR_INVALID 1
#define ERR_ENUMERATION 2
#define ERR_HASH 3
#define ERR_JSON 4

typedef struct {
    char *path;
    off_t size;
    char sha256[65];  
} FileInfo;

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} StringBuilder;

 
static FileInfo *file_list = NULL;
static size_t file_count = 0;
static size_t file_capacity = 0;

 
static int sb_init(StringBuilder *sb) {
    sb->capacity = 1024;
    sb->length = 0;
    sb->data = malloc(sb->capacity);
    if (!sb->data) return -1;
    sb->data[0] = '\0';
    return 0;
}

static int sb_append(StringBuilder *sb, const char *fmt, ...) {
    va_list ap;
    char *tmp;
    int needed;
    va_start(ap, fmt);
    needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (needed < 0) return -1;
    if (sb->length + needed + 1 > sb->capacity) {
        size_t newcap = sb->capacity * 2;
        while (newcap < sb->length + needed + 1) newcap *= 2;
        tmp = realloc(sb->data, newcap);
        if (!tmp) return -1;
        sb->data = tmp;
        sb->capacity = newcap;
    }
    va_start(ap, fmt);
    vsnprintf(sb->data + sb->length, sb->capacity - sb->length, fmt, ap);
    va_end(ap);
    sb->length += needed;
    return 0;
}

 
static int sb_append_escaped(StringBuilder *sb, const char *s) {
    const char *p = s;
    while (*p) {
        if (*p == '\"' || *p == '\\') {
            if (sb_append(sb, "\\%c", *p) != 0) return -1;
        } else if ((unsigned char)*p < 0x20) {
             
            if (sb_append(sb, "\\u%04x", (unsigned char)*p) != 0) return -1;
        } else {
            if (sb_append(sb, "%c", *p) != 0) return -1;
        }
        p++;
    }
    return 0;
}

 
static int compute_sha256_hex(const char *path, char out_hex[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    unsigned char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (EVP_DigestUpdate(mdctx, buf, n) != 1) {
            fclose(f);
            EVP_MD_CTX_free(mdctx);
            return -1;
        }
    }
    if (ferror(f)) {
        fclose(f);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    fclose(f);
    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &md_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    EVP_MD_CTX_free(mdctx);
    for (unsigned int i = 0; i < md_len; i++) {
        sprintf(out_hex + i * 2, "%02x", hash[i]);
    }
    out_hex[64] = '\0';
    return 0;
}

 
static int nftw_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)ftwbuf;
    if (typeflag != FTW_F) return 0;
    if (!S_ISREG(sb->st_mode)) return 0;

    char real_path[PATH_MAX];
    if (!realpath(fpath, real_path)) return 0;  

    if (file_count == file_capacity) {
        size_t newcap = file_capacity ? file_capacity * 2 : 64;
        FileInfo *tmp = realloc(file_list, newcap * sizeof(FileInfo));
        if (!tmp) return -1;  
        file_list = tmp;
        file_capacity = newcap;
    }

    FileInfo *info = &file_list[file_count];
    info->path = strdup(real_path);
    if (!info->path) return -1;
    info->size = sb->st_size;
    if (compute_sha256_hex(real_path, info->sha256) != 0) {
        free(info->path);
        return -1;
    }
    file_count++;
    return 0;
}

 
int filesystem_processing_and_reporting(char *target_dir) {
    struct stat st;
    if (!target_dir) {
        fprintf(stderr, "Error: target_dir is NULL\n");
        return ERR_DIR_INVALID;
    }
    if (stat(target_dir, &st) != 0 || !S_ISDIR(st.st_mode) || access(target_dir, R_OK) != 0) {
        fprintf(stderr, "Error: directory '%s' is invalid or not readable\n", target_dir);
        return ERR_DIR_INVALID;
    }

     
    struct timespec start, end;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        fprintf(stderr, "Error: clock_gettime failed\n");
        return ERR_ENUMERATION;
    }

     
    int nftw_flags = FTW_PHYS;
    if (nftw(target_dir, nftw_callback, 20, nftw_flags) != 0) {
        fprintf(stderr, "Error: directory traversal failed\n");
        return ERR_ENUMERATION;
    }

     
    off_t total_bytes = 0;
    for (size_t i = 0; i < file_count; i++) {
        total_bytes += file_list[i].size;
    }

     
    StringBuilder sb;
    if (sb_init(&sb) != 0) {
        fprintf(stderr, "Error: JSON builder init failed\n");
        return ERR_JSON;
    }
    if (sb_append(&sb, "{\n") != 0) goto json_err;
    if (sb_append(&sb, "  \"processed_files\": [\n") != 0) goto json_err;
    for (size_t i = 0; i < file_count; i++) {
        FileInfo *fi = &file_list[i];
        if (sb_append(&sb, "    {\"path\":\"") != 0) goto json_err;
        if (sb_append_escaped(&sb, fi->path) != 0) goto json_err;
        if (sb_append(&sb, "\",\"size\":%jd,\"sha256\":\"%s\"}",
                      (intmax_t)fi->size, fi->sha256) != 0) goto json_err;
        if (i + 1 < file_count) {
            if (sb_append(&sb, ",\n") != 0) goto json_err;
        } else {
            if (sb_append(&sb, "\n") != 0) goto json_err;
        }
    }
    if (sb_append(&sb, "  ],\n") != 0) goto json_err;
    if (sb_append(&sb, "  \"summary\": {\n") != 0) goto json_err;
    if (sb_append(&sb, "    \"total_files\": %zu,\n", file_count) != 0) goto json_err;
    if (sb_append(&sb, "    \"total_bytes\": %jd,\n", (intmax_t)total_bytes) != 0) goto json_err;

     
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
        fprintf(stderr, "Error: clock_gettime end failed\n");
        return ERR_JSON;
    }
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    if (sb_append(&sb, "    \"processing_time_seconds\": %.6f\n", elapsed) != 0) goto json_err;
    if (sb_append(&sb, "  }\n") != 0) goto json_err;
    if (sb_append(&sb, "}\n") != 0) goto json_err;

     
    char tmp_name[] = "filesystem_report.json.tmpXXXXXX";
    int fd = mkstemp(tmp_name);
    if (fd == -1) {
        fprintf(stderr, "Error: cannot create temporary file\n");
        free(sb.data);
        return ERR_JSON;
    }
    FILE *tmp_fp = fdopen(fd, "w");
    if (!tmp_fp) {
        close(fd);
        unlink(tmp_name);
        free(sb.data);
        fprintf(stderr, "Error: fdopen failed\n");
        return ERR_JSON;
    }
    if (fwrite(sb.data, 1, sb.length, tmp_fp) != sb.length) {
        fclose(tmp_fp);
        unlink(tmp_name);
        free(sb.data);
        fprintf(stderr, "Error: writing JSON failed\n");
        return ERR_JSON;
    }
    fflush(tmp_fp);
    fclose(tmp_fp);
    if (rename(tmp_name, "filesystem_report.json") != 0) {
        unlink(tmp_name);
        free(sb.data);
        fprintf(stderr, "Error: rename to filesystem_report.json failed\n");
        return ERR_JSON;
    }
    free(sb.data);

     
    printf("Processed %zu files, %jd bytes in %.6f seconds\n",
           file_count, (intmax_t)total_bytes, elapsed);

     
    for (size_t i = 0; i < file_count; i++) {
        free(file_list[i].path);
    }
    free(file_list);
    file_list = NULL;
    file_count = 0;
    file_capacity = 0;
    return 0;

json_err:
    free(sb.data);
    fprintf(stderr, "Error: JSON building failed\n");
    return ERR_JSON;
}