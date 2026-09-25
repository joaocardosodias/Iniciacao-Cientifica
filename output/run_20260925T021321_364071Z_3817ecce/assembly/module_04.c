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
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/evp.h>

#define BUFFER_SIZE 65536

 
#define ERR_SUCCESS 0
#define ERR_IO 1
#define ERR_HASH 2
#define ERR_JSON 3

 
static int append_str(char **buf, size_t *len, size_t *cap, const char *s)
{
    size_t add = strlen(s);
    if (*len + add + 1 > *cap) {
        size_t newcap = (*cap ? *cap : 128);
        while (*len + add + 1 > newcap)
            newcap *= 2;
        char *newbuf = realloc(*buf, newcap);
        if (!newbuf)
            return -1;
        *buf = newbuf;
        *cap = newcap;
    }
    memcpy(*buf + *len, s, add);
    *len += add;
    (*buf)[*len] = '\0';
    return 0;
}

 
static char *hex_encode(const unsigned char *digest, size_t len)
{
    const char hexchars[] = "0123456789abcdef";
    char *out = malloc(len * 2 + 1);
    if (!out)
        return NULL;
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = hexchars[(digest[i] >> 4) & 0xF];
        out[i * 2 + 1] = hexchars[digest[i] & 0xF];
    }
    out[len * 2] = '\0';
    return out;
}

 
static int compute_sha256(const char *path, unsigned char *out_digest, size_t *out_size)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "Error opening file \"%s\": %s\n", path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fileno(fp), &st) != 0) {
        fprintf(stderr, "Error stating file \"%s\": %s\n", path, strerror(errno));
        fclose(fp);
        return -1;
    }
    *out_size = (size_t)st.st_size;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed for \"%s\"\n", path);
        fclose(fp);
        return -1;
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed for \"%s\"\n", path);
        EVP_MD_CTX_free(mdctx);
        fclose(fp);
        return -1;
    }

    unsigned char *buffer = malloc(BUFFER_SIZE);
    if (!buffer) {
        EVP_MD_CTX_free(mdctx);
        fclose(fp);
        return -1;
    }

    size_t read_bytes;
    while ((read_bytes = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, read_bytes) != 1) {
            fprintf(stderr, "EVP_DigestUpdate failed for \"%s\"\n", path);
            free(buffer);
            EVP_MD_CTX_free(mdctx);
            fclose(fp);
            return -1;
        }
    }
    if (ferror(fp)) {
        fprintf(stderr, "Error reading file \"%s\"\n", path);
        free(buffer);
        EVP_MD_CTX_free(mdctx);
        fclose(fp);
        return -1;
    }

    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(mdctx, out_digest, &md_len) != 1) {
        fprintf(stderr, "EVP_DigestFinal_ex failed for \"%s\"\n", path);
        free(buffer);
        EVP_MD_CTX_free(mdctx);
        fclose(fp);
        return -1;
    }

    free(buffer);
    EVP_MD_CTX_free(mdctx);
    fclose(fp);
    return 0;
}

 
int hashing_reporting_and_summary_generation(const char **file_paths,
                                             size_t file_count,
                                             const char *json_report_path)
{
    unsigned int error_code = ERR_SUCCESS;
    size_t total_bytes = 0;
    size_t processed_successfully = 0;
    size_t failed = 0;

    char *json_buf = NULL;
    size_t json_len = 0;
    size_t json_cap = 0;

    if (append_str(&json_buf, &json_len, &json_cap,
                   "{\n    \"files\": [\n") != 0) {
        error_code = ERR_JSON;
        goto cleanup;
    }

    int first_entry = 1;
    for (size_t i = 0; i < file_count; ++i) {
        const char *path = file_paths[i];
        unsigned char digest[EVP_MAX_MD_SIZE];
        size_t file_size = 0;

        if (compute_sha256(path, digest, &file_size) != 0) {
            failed++;
            if (error_code == ERR_SUCCESS)
                error_code = ERR_IO;    
            continue;
        }

        char *hex = hex_encode(digest, 32);
        if (!hex) {
            failed++;
            if (error_code == ERR_SUCCESS)
                error_code = ERR_HASH;
            continue;
        }

        char entry[1024];
        int entry_len = snprintf(entry, sizeof(entry),
                                 "        { \"path\": \"%s\", \"size\": %zu, \"sha256\": \"%s\" }%s\n",
                                 path, file_size, hex,
                                 (i == file_count - 1) ? "" : ",");
        free(hex);
        if (entry_len < 0 || (size_t)entry_len >= sizeof(entry)) {
            failed++;
            if (error_code == ERR_SUCCESS)
                error_code = ERR_JSON;
            continue;
        }

        if (!first_entry) {
             
            if (json_len > 0 && json_buf[json_len - 2] == ',')
                json_buf[json_len - 2] = '\n';
        }
        first_entry = 0;

        if (append_str(&json_buf, &json_len, &json_cap, entry) != 0) {
            failed++;
            if (error_code == ERR_SUCCESS)
                error_code = ERR_JSON;
            continue;
        }

        total_bytes += file_size;
        processed_successfully++;
    }

    if (append_str(&json_buf, &json_len, &json_cap,
                   "    ],\n    \"summary\": {\n") != 0) {
        error_code = ERR_JSON;
        goto cleanup;
    }

    char summary[512];
    int summary_len = snprintf(summary, sizeof(summary),
                               "        \"total_files\": %zu,\n"
                               "        \"total_bytes\": %zu,\n"
                               "        \"processed_successfully\": %zu,\n"
                               "        \"failed\": %zu\n",
                               file_count, total_bytes,
                               processed_successfully, failed);
    if (summary_len < 0 || (size_t)summary_len >= sizeof(summary)) {
        error_code = ERR_JSON;
        goto cleanup;
    }

    if (append_str(&json_buf, &json_len, &json_cap, summary) != 0) {
        error_code = ERR_JSON;
        goto cleanup;
    }

    if (append_str(&json_buf, &json_len, &json_cap,
                   "    }\n}\n") != 0) {
        error_code = ERR_JSON;
        goto cleanup;
    }

    FILE *out_fp = fopen(json_report_path, "w");
    if (!out_fp) {
        fprintf(stderr, "Error opening JSON report file \"%s\": %s\n",
                json_report_path, strerror(errno));
        if (error_code == ERR_SUCCESS)
            error_code = ERR_IO;
        goto cleanup;
    }

    if (fwrite(json_buf, 1, json_len, out_fp) != json_len) {
        fprintf(stderr, "Error writing to JSON report file \"%s\"\n",
                json_report_path);
        if (error_code == ERR_SUCCESS)
            error_code = ERR_IO;
        fclose(out_fp);
        goto cleanup;
    }

    fclose(out_fp);

cleanup:
    free(json_buf);
    return (error_code == ERR_SUCCESS) ? 0 : (int)error_code;
}