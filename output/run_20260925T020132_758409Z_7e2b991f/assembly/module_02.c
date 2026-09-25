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
}

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
} file_hash_error_t;

 
static int compute_sha256(const char *filepath, unsigned char *out_digest, off_t *out_size)
{
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        fprintf(stderr, "Error opening file '%s': %s\n", filepath, strerror(errno));
        return FH_ERR_OPENFILE;
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx)) {
        fclose(fp);
        fprintf(stderr, "SHA256_Init failed\n");
        return FH_ERR_HASH;
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

    const size_t bufsize = 8192;
    unsigned char *buf = malloc(bufsize);
    if (!buf) {
        fclose(fp);
        fprintf(stderr, "Memory allocation failure\n");
        return FH_ERR_HASH;
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
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

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}
        total += n;
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

    if (ferror(fp)) {
        free(buf);
        fclose(fp);
        fprintf(stderr, "Error reading file '%s'\n", filepath);
        return FH_ERR_READ;
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

    if (!SHA256_Final(out_digest, &ctx)) {
        free(buf);
        fclose(fp);
        fprintf(stderr, "SHA256_Final failed\n");
        return FH_ERR_HASH;
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

    free(buf);
    fclose(fp);
    *out_size = total;
    return FH_SUCCESS;
}

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

 
static void digest_to_hex(const unsigned char *digest, char *hexbuf)
{
    static const char hexchars[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        hexbuf[i * 2] = hexchars[(digest[i] >> 4) & 0xF];
        hexbuf[i * 2 + 1] = hexchars[digest[i] & 0xF];
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}
    hexbuf[64] = '\0';
}

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

 
static int json_write_entry(FILE *f, const char *path, off_t size, const char *sha256_hex, int is_first)
{
    if (!is_first) {
        if (fprintf(f, ",\n") < 0)
            return FH_ERR_JSON;
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}
    if (fprintf(f,
                "  {\n"
                "    \"path\": \"%s\",\n"
                "    \"size\": %jd,\n"
                "    \"sha256\": \"%s\"\n"
                "  }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}",
                path,
                (intmax_t)size,
                sha256_hex) < 0)
        return FH_ERR_JSON;
    return FH_SUCCESS;
}

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

 
int file_hash_reporter(const char *directory_path)
{
    if (!directory_path) {
        fprintf(stderr, "Directory path is NULL\n");
        return FH_ERR_INVALID_ARG;
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

    DIR *dir = opendir(directory_path);
    if (!dir) {
        fprintf(stderr, "Cannot open directory '%s': %s\n", directory_path, strerror(errno));
        return FH_ERR_OPENDIR;
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

    FILE *json_fp = fopen("file_hash_report.json", "w");
    if (!json_fp) {
        fprintf(stderr, "Cannot create JSON report file: %s\n", strerror(errno));
        closedir(dir);
        return FH_ERR_JSON;
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

    if (fprintf(json_fp, "[\n") < 0) {
        fprintf(stderr, "Error writing to JSON file\n");
        fclose(json_fp);
        closedir(dir);
        return FH_ERR_JSON;
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
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

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

        struct stat st;
        if (stat(full_path, &st) != 0) {
            fprintf(stderr, "stat failed for '%s': %s\n", full_path, strerror(errno));
            continue;
        }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

        if (!S_ISREG(st.st_mode))
            continue;  

        unsigned char digest[32];
        off_t filesize = 0;
        int rc = compute_sha256(full_path, digest, &filesize);
        if (rc != FH_SUCCESS) {
             
            continue;
        }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

        char sha256_hex[65];
        digest_to_hex(digest, sha256_hex);

        rc = json_write_entry(json_fp, full_path, filesize, sha256_hex, first);
        if (rc != FH_SUCCESS) {
            fprintf(stderr, "Failed to write JSON entry for '%s'\n", full_path);
            continue;
        }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

        if (first)
            first = 0;

        total_files++;
        total_bytes += filesize;
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

    if (fprintf(json_fp, "\n]\n") < 0) {
        fprintf(stderr, "Error finalizing JSON file\n");
        fclose(json_fp);
        closedir(dir);
        return FH_ERR_JSON;
    }

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}

    fclose(json_fp);
    closedir(dir);

    printf("Processed %d files, total size %jd bytes. Report written to file_hash_report.json\n",
           total_files, (intmax_t)total_bytes);
    return FH_SUCCESS;
}

int f02(const char *directory_path) {
    return file_hash_reporter(directory_path);
}