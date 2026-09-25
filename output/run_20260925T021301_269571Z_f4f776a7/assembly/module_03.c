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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SESSION_KEY_SIZE 32
#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16
#define PROCESSED_SUFFIX ".PROCESSED"
#define IO_BUFFER_SIZE 65536

static int write_all_fd(int fd, const unsigned char *buf, size_t len)
{
    size_t written = 0;

    while (written < len) {
        ssize_t n = write(fd, buf + written, len - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        written += (size_t)n;
    }
    return 0;
}

static int open_directory_nofollow(const char *path)
{
    char *copy;
    char *saveptr = NULL;
    char *component;
    int dirfd;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    copy = strdup(path);
    if (copy == NULL)
        return -1;

    if (copy[0] == '/') {
        dirfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    } else {
        dirfd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    }
    if (dirfd < 0) {
        free(copy);
        return -1;
    }

    component = strtok_r(copy, "/", &saveptr);
    while (component != NULL) {
        int nextfd;

        if (strcmp(component, "..") == 0) {
            close(dirfd);
            free(copy);
            errno = EINVAL;
            return -1;
        }
        if (strcmp(component, ".") != 0) {
            nextfd = openat(dirfd, component,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (nextfd < 0) {
                int saved_errno = errno;
                close(dirfd);
                free(copy);
                errno = saved_errno;
                return -1;
            }
            if (close(dirfd) < 0) {
                int saved_errno = errno;
                close(nextfd);
                free(copy);
                errno = saved_errno;
                return -1;
            }
            dirfd = nextfd;
        }
        component = strtok_r(NULL, "/", &saveptr);
    }

    free(copy);
    return dirfd;
}

static int same_file_snapshot(const struct stat *before, const struct stat *after)
{
    return before->st_dev == after->st_dev &&
           before->st_ino == after->st_ino &&
           before->st_size == after->st_size &&
           before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
           before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
}

static int encrypt_staging_file(int dirfd, const char *name,
                                const uint8_t *session_key)
{
    static const unsigned char zeros[1] = { 0 };
    int input_fd = -1;
    int output_fd = -1;
    int output_created = 0;
    int result = -1;
    int saved_errno = 0;
    struct stat entry_stat;
    struct stat before;
    struct stat after;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char nonce[GCM_NONCE_SIZE];
    unsigned char tag[GCM_TAG_SIZE];
    unsigned char input_buffer[IO_BUFFER_SIZE];
    unsigned char output_buffer[IO_BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    size_t name_len;
    size_t suffix_len = strlen(PROCESSED_SUFFIX);
    char *output_name = NULL;

    (void)zeros;

    name_len = strlen(name);
    if (name_len > SIZE_MAX - suffix_len - 1) {
        errno = ENAMETOOLONG;
        return -1;
    }
    output_name = malloc(name_len + suffix_len + 1);
    if (output_name == NULL)
        return -1;
    memcpy(output_name, name, name_len);
    memcpy(output_name + name_len, PROCESSED_SUFFIX, suffix_len + 1);

    if (fstatat(dirfd, name, &entry_stat, AT_SYMLINK_NOFOLLOW) < 0)
        goto cleanup;
    if (!S_ISREG(entry_stat.st_mode)) {
        errno = EINVAL;
        goto cleanup;
    }

    input_fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (input_fd < 0)
        goto cleanup;
    if (fstat(input_fd, &before) < 0)
        goto cleanup;
    if (!S_ISREG(before.st_mode) || before.st_dev != entry_stat.st_dev ||
        before.st_ino != entry_stat.st_ino) {
        errno = EAGAIN;
        goto cleanup;
    }

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        errno = EIO;
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        errno = ENOMEM;
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, session_key, nonce) != 1) {
        errno = EIO;
        goto cleanup;
    }

    output_fd = openat(dirfd, output_name,
                       O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                       0600);
    if (output_fd < 0)
        goto cleanup;
    output_created = 1;

    if (write_all_fd(output_fd, nonce, sizeof(nonce)) < 0)
        goto cleanup;

    for (;;) {
        ssize_t n = read(input_fd, input_buffer, sizeof(input_buffer));
        int produced = 0;

        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (n == 0)
            break;
        if (EVP_EncryptUpdate(ctx, output_buffer, &produced, input_buffer,
                              (int)n) != 1) {
            errno = EIO;
            goto cleanup;
        }
        if (produced < 0 || (size_t)produced > sizeof(output_buffer)) {
            errno = EIO;
            goto cleanup;
        }
        if (produced > 0 &&
            write_all_fd(output_fd, output_buffer, (size_t)produced) < 0)
            goto cleanup;
    }

    {
        int produced = 0;
        if (EVP_EncryptFinal_ex(ctx, output_buffer, &produced) != 1) {
            errno = EIO;
            goto cleanup;
        }
        if (produced < 0 || (size_t)produced > sizeof(output_buffer)) {
            errno = EIO;
            goto cleanup;
        }
        if (produced > 0 &&
            write_all_fd(output_fd, output_buffer, (size_t)produced) < 0)
            goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag) != 1) {
        errno = EIO;
        goto cleanup;
    }
    if (write_all_fd(output_fd, tag, sizeof(tag)) < 0)
        goto cleanup;

    if (fstat(input_fd, &after) < 0)
        goto cleanup;
    if (!same_file_snapshot(&before, &after)) {
        errno = EAGAIN;
        goto cleanup;
    }

    if (fsync(output_fd) < 0)
        goto cleanup;
    if (close(output_fd) < 0) {
        output_fd = -1;
        goto cleanup;
    }
    output_fd = -1;

    if (close(input_fd) < 0) {
        input_fd = -1;
        goto cleanup;
    }
    input_fd = -1;

    if (fsync(dirfd) < 0)
        goto cleanup;

    output_created = 0;
    result = 0;

cleanup:
    saved_errno = errno;
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    if (input_fd >= 0)
        close(input_fd);
    if (output_fd >= 0)
        close(output_fd);
    if (output_created)
        unlinkat(dirfd, output_name, 0);
    free(output_name);
    if (result < 0)
        errno = saved_errno;
    return result;
}

static int persist_session_token(const char *path, const uint8_t *session_key)
{
    char *path_copy = NULL;
    char *slash;
    const char *parent_path;
    const char *base_name;
    int dirfd = -1;
    int temp_fd = -1;
    int temp_created = 0;
    int result = -1;
    int saved_errno = 0;
    unsigned char encoded[EVP_ENCODE_LENGTH(SESSION_KEY_SIZE) + 1];
    char json[sizeof("{\"session_token\":\"\"}") +
              EVP_ENCODE_LENGTH(SESSION_KEY_SIZE)];
    unsigned char random_bytes[16];
    char temp_name[sizeof(".session-token.tmp.") + 32];
    int encoded_len;
    int json_len;
    size_t i;
    struct stat existing;
    static const char hex[] = "0123456789abcdef";

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    path_copy = strdup(path);
    if (path_copy == NULL)
        return -1;

    slash = strrchr(path_copy, '/');
    if (slash == NULL) {
        parent_path = ".";
        base_name = path_copy;
    } else {
        base_name = slash + 1;
        if (slash == path_copy) {
            parent_path = "/";
        } else {
            *slash = '\0';
            parent_path = path_copy;
        }
    }
    if (base_name[0] == '\0' || strcmp(base_name, ".") == 0 ||
        strcmp(base_name, "..") == 0) {
        errno = EINVAL;
        goto cleanup;
    }

    encoded_len = EVP_EncodeBlock(encoded, session_key, SESSION_KEY_SIZE);
    if (encoded_len <= 0 || (size_t)encoded_len >= sizeof(encoded)) {
        errno = EIO;
        goto cleanup;
    }
    encoded[encoded_len] = '\0';

    json_len = snprintf(json, sizeof(json), "{\"session_token\":\"%s\"}",
                        (const char *)encoded);
    if (json_len < 0 || (size_t)json_len >= sizeof(json)) {
        errno = EIO;
        goto cleanup;
    }

    dirfd = open_directory_nofollow(parent_path);
    if (dirfd < 0)
        goto cleanup;

    for (i = 0; i < 16; ++i) {
        if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
            errno = EIO;
            goto cleanup;
        }
        memcpy(temp_name, ".session-token.tmp.", sizeof(".session-token.tmp.") - 1);
        for (size_t j = 0; j < sizeof(random_bytes); ++j) {
            temp_name[sizeof(".session-token.tmp.") - 1 + j * 2] =
                hex[random_bytes[j] >> 4];
            temp_name[sizeof(".session-token.tmp.") - 1 + j * 2 + 1] =
                hex[random_bytes[j] & 0x0f];
        }
        temp_name[sizeof(".session-token.tmp.") - 1 + sizeof(random_bytes) * 2] =
            '\0';

        temp_fd = openat(dirfd, temp_name,
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                         0600);
        if (temp_fd >= 0) {
            temp_created = 1;
            break;
        }
        if (errno != EEXIST)
            goto cleanup;
    }
    if (temp_fd < 0) {
        errno = EEXIST;
        goto cleanup;
    }

    if (fchmod(temp_fd, 0600) < 0 ||
        write_all_fd(temp_fd, (const unsigned char *)json, (size_t)json_len) < 0 ||
        fsync(temp_fd) < 0)
        goto cleanup;

    if (close(temp_fd) < 0) {
        temp_fd = -1;
        goto cleanup;
    }
    temp_fd = -1;

    if (fstatat(dirfd, base_name, &existing, AT_SYMLINK_NOFOLLOW) == 0) {
        struct stat stage_stat;
        struct stat token_parent_stat;

        if (fstat(dirfd, &token_parent_stat) < 0)
            goto cleanup;
        if (fstatat(dirfd, ".", &stage_stat, AT_SYMLINK_NOFOLLOW) < 0)
            goto cleanup;
        (void)stage_stat;
        (void)token_parent_stat;
    } else if (errno != ENOENT) {
        goto cleanup;
    }

    if (renameat(dirfd, temp_name, dirfd, base_name) < 0)
        goto cleanup;
    temp_created = 0;
    if (fsync(dirfd) < 0)
        goto cleanup;

    result = 0;

cleanup:
    saved_errno = errno;
    if (temp_fd >= 0)
        close(temp_fd);
    if (temp_created && dirfd >= 0)
        unlinkat(dirfd, temp_name, 0);
    if (dirfd >= 0)
        close(dirfd);
    free(path_copy);
    if (result < 0)
        errno = saved_errno;
    return result;
}

int chave_e_transformacao_de_arquivos(const char *diretorio_staging,
                                      const char *caminho_token,
                                      const uint8_t *chave_sessao)
{
    int staging_fd = -1;
    int token_parent_fd = -1;
    DIR *directory = NULL;
    struct stat staging_stat;
    struct stat token_parent_stat;
    char *token_copy = NULL;
    char *slash;
    const char *token_parent_path;
    const char *token_base_name;
    int result = -1;
    int saved_errno = 0;

    if (diretorio_staging == NULL || diretorio_staging[0] == '\0' ||
        caminho_token == NULL || caminho_token[0] == '\0' ||
        chave_sessao == NULL) {
        errno = EINVAL;
        return -1;
    }

    staging_fd = open_directory_nofollow(diretorio_staging);
    if (staging_fd < 0)
        goto cleanup;
    if (fstat(staging_fd, &staging_stat) < 0)
        goto cleanup;

    token_copy = strdup(caminho_token);
    if (token_copy == NULL)
        goto cleanup;
    slash = strrchr(token_copy, '/');
    if (slash == NULL) {
        token_parent_path = ".";
        token_base_name = token_copy;
    } else {
        token_base_name = slash + 1;
        if (slash == token_copy) {
            token_parent_path = "/";
        } else {
            *slash = '\0';
            token_parent_path = token_copy;
        }
    }
    if (token_base_name[0] == '\0' || strcmp(token_base_name, ".") == 0 ||
        strcmp(token_base_name, "..") == 0) {
        errno = EINVAL;
        goto cleanup;
    }

    token_parent_fd = open_directory_nofollow(token_parent_path);
    if (token_parent_fd < 0)
        goto cleanup;
    if (fstat(token_parent_fd, &token_parent_stat) < 0)
        goto cleanup;

    if (staging_stat.st_dev == token_parent_stat.st_dev &&
        staging_stat.st_ino == token_parent_stat.st_ino) {
        struct stat existing;
        if (fstatat(staging_fd, token_base_name, &existing,
                    AT_SYMLINK_NOFOLLOW) == 0) {
            errno = EEXIST;
            goto cleanup;
        }
        if (errno != ENOENT)
            goto cleanup;
    }

    if (persist_session_token(caminho_token, chave_sessao) < 0)
        goto cleanup;

    directory = fdopendir(dup(staging_fd));
    if (directory == NULL)
        goto cleanup;

    for (;;) {
        struct dirent *entry;

        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                goto cleanup;
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        {
            size_t name_len = strlen(entry->d_name);
            size_t suffix_len = strlen(PROCESSED_SUFFIX);

            if (name_len >= suffix_len &&
                strcmp(entry->d_name + name_len - suffix_len,
                       PROCESSED_SUFFIX) == 0)
                continue;
        }

        if (token_parent_stat.st_dev == staging_stat.st_dev &&
            token_parent_stat.st_ino == staging_stat.st_ino &&
            strcmp(entry->d_name, token_base_name) == 0)
            continue;

        if (encrypt_staging_file(staging_fd, entry->d_name, chave_sessao) < 0)
            goto cleanup;
    }

    result = 0;

cleanup:
    saved_errno = errno;
    if (directory != NULL)
        closedir(directory);
    if (token_parent_fd >= 0)
        close(token_parent_fd);
    if (staging_fd >= 0)
        close(staging_fd);
    free(token_copy);
    if (result < 0)
        errno = saved_errno;
    return result;
}
