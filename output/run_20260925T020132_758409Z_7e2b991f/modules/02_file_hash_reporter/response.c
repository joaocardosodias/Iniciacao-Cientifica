#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/sha.h>

typedef enum {
    FH_SUCCESS = 0,
    FH_ERR_INVALID_ARG = 1,
    FH_ERR_OPENDIR = 2,
    FH_ERR_STAT = 3,
    FH_ERR_OPENFILE = 4,
    FH_ERR_READ = 5,
    FH_ERR_HASH = 6,
    FH_ERR_JSON = 7
} file_hash_error_t;

/* Helper: compute SHA-256 of a file.
   Returns 0 on success, non‑zero on failure.
   On success, *out_size receives file size,
   and *out_digest contains 32‑byte hash. */
static int compute_sha256(const char *filepath, unsigned char *out_digest, off_t *out_size)
{
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        fprintf(stderr, "Error opening file '%s': %s\n", filepath, strerror(errno));
        return FH_ERR_OPENFILE;
    }

    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx)) {
        fclose(fp);
        fprintf(stderr, "SHA256_Init failed\n");
        return FH_ERR_HASH;
    }

    const size_t bufsize = 8192;
    unsigned char *buf = malloc(bufsize);
    if (!buf) {
        fclose(fp);
        fprintf(stderr, "Memory allocation failure\n");
        return FH_ERR_HASH;
    }

    off_t total = 0;
    size_t n;
    while ((n = fread(buf, 1, bufsize, fp)) > 0) {
        if (!SHA256_Update(&ctx, buf, n)) {
            free(buf);
            fclose(fp);
            fprintf(stderr, "SHA256_Update failed\n");
            return FH_ERR_HASH;
        }
        total += n;
    }

    if (ferror(fp)) {
        free(buf);
        fclose(fp);
        fprintf(stderr, "Error reading file '%s'\n", filepath);
        return FH_ERR_READ;
    }

    if (!SHA256_Final(out_digest, &ctx)) {
        free(buf);
        fclose(fp);
        fprintf(stderr, "SHA256_Final failed\n");
        return FH_ERR_HASH;
    }

    free(buf);
    fclose(fp);
    *out_size = total;
    return FH_SUCCESS;
}

/* Helper: convert 32‑byte digest to hex string (64 chars + NUL). */
static void digest_to_hex(const unsigned char *digest, char *hexbuf)
{
    static const char hexchars[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        hexbuf[i * 2] = hexchars[(digest[i] >> 4) & 0xF];
        hexbuf[i * 2 + 1] = hexchars[digest[i] & 0xF];
    }
    hexbuf[64] = '\0';
}

/* Helper: write a JSON object entry. */
static int json_write_entry(FILE *f, const char *path, off_t size, const char *sha256_hex, int is_first)
{
    if (!is_first) {
        if (fprintf(f, ",\n") < 0)
            return FH_ERR_JSON;
    }
    if (fprintf(f,
                "  {\n"
                "    \"path\": \"%s\",\n"
                "    \"size\": %jd,\n"
                "    \"sha256\": \"%s\"\n"
                "  }",
                path,
                (intmax_t)size,
                sha256_hex) < 0)
        return FH_ERR_JSON;
    return FH_SUCCESS;
}

/* Public API */
int file_hash_reporter(const char *directory_path)
{
    if (!directory_path) {
        fprintf(stderr, "Directory path is NULL\n");
        return FH_ERR_INVALID_ARG;
    }

    DIR *dir = opendir(directory_path);
    if (!dir) {
        fprintf(stderr, "Cannot open directory '%s': %s\n", directory_path, strerror(errno));
        return FH_ERR_OPENDIR;
    }

    FILE *json_fp = fopen("file_hash_report.json", "w");
    if (!json_fp) {
        fprintf(stderr, "Cannot create JSON report file: %s\n", strerror(errno));
        closedir(dir);
        return FH_ERR_JSON;
    }

    if (fprintf(json_fp, "[\n") < 0) {
        fprintf(stderr, "Error writing to JSON file\n");
        fclose(json_fp);
        closedir(dir);
        return FH_ERR_JSON;
    }

    struct dirent *entry;
    int first = 1;
    int total_files = 0;
    off_t total_bytes = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char full_path[PATH_MAX];
        if (snprintf(full_path, sizeof(full_path), "%s/%s", directory_path, entry->d_name) >= (int)sizeof(full_path)) {
            fprintf(stderr, "Path too long: %s/%s\n", directory_path, entry->d_name);
            continue;
        }

        struct stat st;
        if (stat(full_path, &st) != 0) {
            fprintf(stderr, "stat failed for '%s': %s\n", full_path, strerror(errno));
            continue;
        }

        if (!S_ISREG(st.st_mode))
            continue; /* skip non‑regular files */

        unsigned char digest[32];
        off_t filesize = 0;
        int rc = compute_sha256(full_path, digest, &filesize);
        if (rc != FH_SUCCESS) {
            /* error already printed inside compute_sha256 */
            continue;
        }

        char sha256_hex[65];
        digest_to_hex(digest, sha256_hex);

        rc = json_write_entry(json_fp, full_path, filesize, sha256_hex, first);
        if (rc != FH_SUCCESS) {
            fprintf(stderr, "Failed to write JSON entry for '%s'\n", full_path);
            continue;
        }

        if (first)
            first = 0;

        total_files++;
        total_bytes += filesize;
    }

    if (fprintf(json_fp, "\n]\n") < 0) {
        fprintf(stderr, "Error finalizing JSON file\n");
        fclose(json_fp);
        closedir(dir);
        return FH_ERR_JSON;
    }

    fclose(json_fp);
    closedir(dir);

    printf("Processed %d files, total size %jd bytes. Report written to file_hash_report.json\n",
           total_files, (intmax_t)total_bytes);
    return FH_SUCCESS;
}