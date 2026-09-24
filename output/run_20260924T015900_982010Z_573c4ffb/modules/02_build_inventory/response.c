#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

struct inventory_entry {
    char *path;
    off_t size;
    mode_t permissions;
    time_t accessed;
    time_t modified;
    time_t changed;
};

struct inventory {
    struct inventory_entry *entries;
    size_t count;
};

/*
 * Initialize inventories to {0} before their first use. On success, out is
 * replaced with the completed inventory; the caller must free any previous
 * inventory first. On failure, out is left unchanged and errno describes the
 * error. Only regular files named in paths are accepted.
 */
void inventory_free(struct inventory *inventory)
{
    size_t i;

    if (inventory == NULL)
        return;

    for (i = 0; i < inventory->count; ++i)
        free(inventory->entries[i].path);

    free(inventory->entries);
    inventory->entries = NULL;
    inventory->count = 0;
}

static int open_directory_at(int parent_fd, const char *component)
{
    struct stat st;
    int fd;
    int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW;

#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif

    if (fstatat(parent_fd, component, &st, AT_SYMLINK_NOFOLLOW) < 0)
        return -1;

    if (S_ISLNK(st.st_mode)) {
        errno = ELOOP;
        return -1;
    }

    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }

    fd = openat(parent_fd, component, flags);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (!S_ISDIR(st.st_mode)) {
        close(fd);
        errno = ENOTDIR;
        return -1;
    }

    return fd;
}

/*
 * Resolve only the parent components of the explicitly supplied path.
 * Each parent component is opened without following symbolic links.
 */
static int open_path_parent(const char *path, char **path_copy_out,
                           char **final_component_out)
{
    char *copy;
    char *cursor;
    int parent_fd;
    int flags = O_RDONLY | O_DIRECTORY;

#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif

    copy = strdup(path);
    if (copy == NULL)
        return -1;

    if (path[0] == '/') {
        parent_fd = open("/", flags);
    } else {
        parent_fd = open(".", flags);
    }

    if (parent_fd < 0) {
        int saved_errno = errno;
        free(copy);
        errno = saved_errno;
        return -1;
    }

    cursor = copy;
    while (*cursor == '/')
        ++cursor;

    if (*cursor == '\0') {
        close(parent_fd);
        free(copy);
        errno = EISDIR;
        return -1;
    }

    for (;;) {
        char *component = cursor;
        char *end;
        char *next;
        int child_fd;

        while (*cursor != '\0' && *cursor != '/')
            ++cursor;

        end = cursor;
        if (*cursor == '/') {
            *cursor++ = '\0';
            while (*cursor == '/')
                ++cursor;
        }

        next = cursor;
        if (next == end + 1)
            next = end;

        if (*next == '\0') {
            if (component[0] == '\0') {
                close(parent_fd);
                free(copy);
                errno = EINVAL;
                return -1;
            }

            *path_copy_out = copy;
            *final_component_out = component;
            return parent_fd;
        }

        child_fd = open_directory_at(parent_fd, component);
        if (child_fd < 0) {
            int saved_errno = errno;
            close(parent_fd);
            free(copy);
            errno = saved_errno;
            return -1;
        }

        close(parent_fd);
        parent_fd = child_fd;
        cursor = next;
    }
}

int build_inventory(const char *const *paths, size_t path_count,
                    struct inventory *out)
{
    struct inventory result = {0};
    size_t i;

    if (out == NULL || (path_count != 0 && paths == NULL)) {
        errno = EINVAL;
        return -1;
    }

    if (path_count > SIZE_MAX / sizeof(*result.entries)) {
        errno = EOVERFLOW;
        return -1;
    }

    if (path_count != 0) {
        result.entries = calloc(path_count, sizeof(*result.entries));
        if (result.entries == NULL)
            return -1;
    }

    for (i = 0; i < path_count; ++i) {
        char *path_copy = NULL;
        char *final_component = NULL;
        struct stat st;
        int parent_fd;

        if (paths[i] == NULL || paths[i][0] == '\0') {
            errno = EINVAL;
            goto fail;
        }

        parent_fd = open_path_parent(paths[i], &path_copy,
                                     &final_component);
        if (parent_fd < 0)
            goto fail;

        if (fstatat(parent_fd, final_component, &st,
                    AT_SYMLINK_NOFOLLOW) < 0) {
            int saved_errno = errno;
            close(parent_fd);
            free(path_copy);
            errno = saved_errno;
            goto fail;
        }

        close(parent_fd);
        free(path_copy);

        if (S_ISLNK(st.st_mode)) {
            errno = ELOOP;
            goto fail;
        }

        if (S_ISDIR(st.st_mode)) {
            errno = EISDIR;
            goto fail;
        }

        if (!S_ISREG(st.st_mode)) {
            errno = EINVAL;
            goto fail;
        }

        if (st.st_size < 0) {
            errno = EOVERFLOW;
            goto fail;
        }

        result.entries[i].path = strdup(paths[i]);
        if (result.entries[i].path == NULL)
            goto fail;

        result.entries[i].size = st.st_size;
        result.entries[i].permissions = st.st_mode & 07777;
        result.entries[i].accessed = st.st_atime;
        result.entries[i].modified = st.st_mtime;
        result.entries[i].changed = st.st_ctime;
        result.count = i + 1;
    }

    *out = result;
    return 0;

fail:
    {
        int saved_errno = errno;
        inventory_free(&result);
        errno = saved_errno;
    }
    return -1;
}

#ifdef BUILD_INVENTORY_TEST
#include <assert.h>

static void make_path(char *buffer, size_t capacity,
                      const char *directory, const char *name)
{
    int length = snprintf(buffer, capacity, "%s/%s", directory, name);

    assert(length >= 0);
    assert((size_t)length < capacity);
}

int main(void)
{
    char directory[] = "/tmp/build-inventory-test-XXXXXX";
    char selected[PATH_MAX];
    char unselected[PATH_MAX];
    char subdirectory[PATH_MAX];
    char link_path[PATH_MAX];
    char missing[PATH_MAX];
    const char *authorized[1];
    struct inventory inventory = {0};
    struct inventory_entry *original_entries;
    int fd;

    assert(mkdtemp(directory) != NULL);

    make_path(selected, sizeof(selected), directory, "selected.dat");
    make_path(unselected, sizeof(unselected), directory, "unselected.dat");
    make_path(subdirectory, sizeof(subdirectory), directory, "subdirectory");
    make_path(link_path, sizeof(link_path), directory, "selected-link");
    make_path(missing, sizeof(missing), directory, "missing.dat");

    fd = open(selected, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    assert(write(fd, "private file contents", 21) == 21);
    assert(close(fd) == 0);

    fd = open(unselected, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    assert(close(fd) == 0);

    assert(mkdir(subdirectory, 0700) == 0);
    assert(symlink(selected, link_path) == 0);
    assert(chmod(selected, 0000) == 0);

    authorized[0] = selected;
    assert(build_inventory(authorized, 1, &inventory) == 0);
    assert(inventory.count == 1);
    assert(strcmp(inventory.entries[0].path, selected) == 0);
    assert(inventory.entries[0].size == 21);
    assert(inventory.entries[0].permissions == 0);
    assert(inventory.entries[0].modified != (time_t)0);

    original_entries = inventory.entries;
    authorized[0] = missing;
    assert(build_inventory(authorized, 1, &inventory) == -1);
    assert(errno == ENOENT);
    assert(inventory.entries == original_entries);
    assert(inventory.count == 1);

    authorized[0] = subdirectory;
    assert(build_inventory(authorized, 1, &inventory) == -1);
    assert(errno == EISDIR);
    assert(inventory.entries == original_entries);

    authorized[0] = link_path;
    assert(build_inventory(authorized, 1, &inventory) == -1);
    assert(errno == ELOOP);
    assert(inventory.entries == original_entries);

    inventory_free(&inventory);
    assert(unlink(link_path) == 0);
    assert(unlink(selected) == 0);
    assert(unlink(unselected) == 0);
    assert(rmdir(subdirectory) == 0);
    assert(rmdir(directory) == 0);

    return 0;
}
#endif