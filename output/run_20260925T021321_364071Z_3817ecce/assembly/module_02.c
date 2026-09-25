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
#include "secure_inventory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#else
#include <fcntl.h>
#endif

 
typedef struct {
    dev_t dev;
    ino_t ino;
} visited_dir_t;

 
typedef struct {
    inventory_result_t *result;
    visited_dir_t *visited;
    size_t visited_count;
    size_t visited_capacity;
} scan_state_t;

 
static int ensure_result_capacity(inventory_result_t *res, size_t min_extra) {
    size_t needed = res->count + min_extra;
    size_t capacity = needed;
    if (capacity < 1024) capacity = 1024;
    if (needed > capacity) capacity = needed;
    if (capacity <= res->count) return 0;  
    inventory_entry_t *new_entries = realloc(res->entries, capacity * sizeof(*new_entries));
    if (!new_entries) return -1;
    res->entries = new_entries;
    return 0;
}

 
static int add_entry(inventory_result_t *res, const char *path, const struct stat *st, int err) {
    if (ensure_result_capacity(res, 1) != 0) return -1;
    inventory_entry_t *e = &res->entries[res->count++];
    e->path = strdup(path);
    if (!e->path) return -1;
    e->error = err;
    e->error_msg = NULL;
    if (err) {
        e->error_msg = strdup(strerror(err));
        if (!e->error_msg) return -1;
        e->type = INVENTORY_TYPE_UNKNOWN;
        e->size = 0;
        e->inode = 0;
        e->device = 0;
        e->atime = 0;
        e->mtime = 0;
        e->ctime = 0;
        return 0;
    }

    if (S_ISREG(st->st_mode)) e->type = INVENTORY_TYPE_REGULAR;
    else if (S_ISDIR(st->st_mode)) e->type = INVENTORY_TYPE_DIRECTORY;
    else if (S_ISLNK(st->st_mode)) e->type = INVENTORY_TYPE_SYMLINK;
    else if (S_ISBLK(st->st_mode)) e->type = INVENTORY_TYPE_BLOCK;
    else if (S_ISCHR(st->st_mode)) e->type = INVENTORY_TYPE_CHARACTER;
    else if (S_ISFIFO(st->st_mode)) e->type = INVENTORY_TYPE_FIFO;
    else if (S_ISSOCK(st->st_mode)) e->type = INVENTORY_TYPE_SOCKET;
    else e->type = INVENTORY_TYPE_UNKNOWN;

    e->size = st->st_size;
    e->inode = st->st_ino;
    e->device = st->st_dev;
    e->atime = st->st_atim.tv_sec;
    e->mtime = st->st_mtim.tv_sec;
    e->ctime = st->st_ctim.tv_sec;
    return 0;
}

 
static int visited_contains(scan_state_t *state, dev_t dev, ino_t ino) {
    for (size_t i = 0; i < state->visited_count; ++i) {
        if (state->visited[i].dev == dev && state->visited[i].ino == ino) {
            return 1;
        }
    }
    return 0;
}

static int visited_push(scan_state_t *state, dev_t dev, ino_t ino) {
    if (state->visited_count == state->visited_capacity) {
        size_t new_cap = state->visited_capacity ? state->visited_capacity * 2 : 128;
        visited_dir_t *new_arr = realloc(state->visited, new_cap * sizeof(*new_arr));
        if (!new_arr) return -1;
        state->visited = new_arr;
        state->visited_capacity = new_cap;
    }
    state->visited[state->visited_count].dev = dev;
    state->visited[state->visited_count].ino = ino;
    state->visited_count++;
    return 0;
}

 
static int scan_directory(const char *dirpath, scan_state_t *state) {
    DIR *dp = opendir(dirpath);
    if (!dp) {
        struct stat st;
        if (lstat(dirpath, &st) == -1) {
            if (add_entry(state->result, dirpath, NULL, errno) != 0) return -1;
        } else {
            if (add_entry(state->result, dirpath, &st, errno) != 0) return -1;
        }
        return 0;
    }

    struct stat dirstat;
    if (lstat(dirpath, &dirstat) == -1) {
        closedir(dp);
        if (add_entry(state->result, dirpath, NULL, errno) != 0) return -1;
        return 0;
    }

     
    if (add_entry(state->result, dirpath, &dirstat, 0) != 0) {
        closedir(dp);
        return -1;
    }

     
    if (visited_contains(state, dirstat.st_dev, dirstat.st_ino)) {
        closedir(dp);
        return 0;
    }
    if (visited_push(state, dirstat.st_dev, dirstat.st_ino) != 0) {
        closedir(dp);
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char child_path[PATH_MAX];
        int len = snprintf(child_path, sizeof(child_path), "%s/%s", dirpath, entry->d_name);
        if (len < 0 || (size_t)len >= sizeof(child_path)) {
             
            if (add_entry(state->result, child_path, NULL, ENAMETOOLONG) != 0) {
                closedir(dp);
                return -1;
            }
            continue;
        }

        struct stat st;
        if (lstat(child_path, &st) == -1) {
            if (add_entry(state->result, child_path, NULL, errno) != 0) {
                closedir(dp);
                return -1;
            }
            continue;
        }

        if (add_entry(state->result, child_path, &st, 0) != 0) {
            closedir(dp);
            return -1;
        }

        if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            if (scan_directory(child_path, state) != 0) {
                closedir(dp);
                return -1;
            }
        }
    }

    closedir(dp);
    return 0;
}

 
inventory_result_t *secure_non_destructive_inventory(const char *start_path) {
    const char *root = (start_path && start_path[0]) ? start_path : "/";
    char abs_path[PATH_MAX];
    if (!realpath(root, abs_path)) {
         
        strncpy(abs_path, root, sizeof(abs_path) - 1);
        abs_path[sizeof(abs_path) - 1] = '\0';
    }

    inventory_result_t *res = calloc(1, sizeof(*res));
    if (!res) return NULL;

    scan_state_t state = {0};
    state.result = res;

    if (scan_directory(abs_path, &state) != 0) {
        free_inventory(res);
        free(state.visited);
        return NULL;
    }

    free(state.visited);
    return res;
}

void free_inventory(inventory_result_t *result) {
    if (!result) return;
    for (size_t i = 0; i < result->count; ++i) {
        free(result->entries[i].path);
        free(result->entries[i].error_msg);
    }
    free(result->entries);
    free(result);
}