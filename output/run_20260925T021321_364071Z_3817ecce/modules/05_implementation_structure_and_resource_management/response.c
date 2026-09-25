// resource_mgmt.h
#ifndef RESOURCE_MGMT_H
#define RESOURCE_MGMT_H

#include <stddef.h>

/* Configuration structure used by the resource‑management module. */
typedef struct {
    const char *config_path;   /* Path to a text configuration file. */
    int         max_lines;     /* Maximum number of lines to process. */
} config_t;

/* Result structure filled on successful execution. */
typedef struct {
    int    processed_lines;    /* Number of lines successfully processed. */
    char  *summary;            /* Dynamically allocated summary string. */
} result_t;

/* Error codes returned by the public API. */
typedef enum {
    RM_OK = 0,
    RM_ERR_NULL_CONFIG,
    RM_ERR_NULL_RESULT,
    RM_ERR_OPEN_FILE,
    RM_ERR_MEMORY,
    RM_ERR_READ_LINE,
    RM_ERR_TOO_MANY_LINES
} rm_error_t;

/**
 * @brief Executes the core resource‑management logic for the gateway.
 *
 * @param config   Pointer to a configuration structure (defined by you).
 * @param out_res  Pointer to a result structure that will be filled on success.
 * @return 0 on success, non‑zero error code on failure.
 */
int implementation_structure_and_resource_management(const config_t *config, result_t *out_res);

#endif /* RESOURCE_MGMT_H */

// resource_mgmt.c
#define _GNU_SOURCE
#include "resource_mgmt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Internal helper: allocate and initialize a result structure. */
static int init_result(result_t *res) {
    if (!res) {
        fprintf(stderr, "init_result: result pointer is NULL\n");
        return RM_ERR_NULL_RESULT;
    }
    res->processed_lines = 0;
    res->summary = NULL;
    return RM_OK;
}

/* Internal helper: free resources held by a result structure. */
static void free_result(result_t *res) {
    if (res && res->summary) {
        free(res->summary);
        res->summary = NULL;
    }
}

/* Internal helper: read up to max_lines from the config file and build a summary. */
static int process_file(FILE *fp, int max_lines, result_t *res) {
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int lines = 0;
    size_t total_len = 0;
    char *summary_buf = NULL;

    while ((read = getline(&line, &len, fp)) != -1) {
        if (max_lines > 0 && lines >= max_lines) {
            fprintf(stderr, "process_file: reached max_lines limit (%d)\n", max_lines);
            free(line);
            return RM_ERR_TOO_MANY_LINES;
        }

        /* Grow the summary buffer. */
        char *new_buf = realloc(summary_buf, total_len + (size_t)read + 1);
        if (!new_buf) {
            fprintf(stderr, "process_file: memory allocation failed\n");
            free(line);
            free(summary_buf);
            return RM_ERR_MEMORY;
        }
        summary_buf = new_buf;
        memcpy(summary_buf + total_len, line, (size_t)read);
        total_len += (size_t)read;
        summary_buf[total_len] = '\0';
        lines++;
    }

    if (ferror(fp)) {
        fprintf(stderr, "process_file: error reading file (%s)\n", strerror(errno));
        free(line);
        free(summary_buf);
        return RM_ERR_READ_LINE;
    }

    free(line);
    res->processed_lines = lines;
    res->summary = summary_buf;
    return RM_OK;
}

/* Public API implementation. */
int implementation_structure_and_resource_management(const config_t *config, result_t *out_res) {
    int ret = RM_OK;
    FILE *fp = NULL;

    /* Parameter validation. */
    if (!config) {
        fprintf(stderr, "implementation_structure_and_resource_management: config is NULL\n");
        return RM_ERR_NULL_CONFIG;
    }
    if (!out_res) {
        fprintf(stderr, "implementation_structure_and_resource_management: out_res is NULL\n");
        return RM_ERR_NULL_RESULT;
    }

    /* Initialize result structure. */
    ret = init_result(out_res);
    if (ret != RM_OK) {
        goto cleanup;
    }

    /* Open the configuration file. */
    fp = fopen(config->config_path, "r");
    if (!fp) {
        fprintf(stderr, "implementation_structure_and_resource_management: cannot open file '%s' (%s)\n",
                config->config_path ? config->config_path : "(null)", strerror(errno));
        ret = RM_ERR_OPEN_FILE;
        goto cleanup;
    }

    /* Process the file contents. */
    ret = process_file(fp, config->max_lines, out_res);
    if (ret != RM_OK) {
        goto cleanup;
    }

    /* Success path falls through to cleanup. */
cleanup:
    if (fp) {
        fclose(fp);
        fp = NULL;
    }
    if (ret != RM_OK) {
        /* Ensure no leaked memory on error. */
        free_result(out_res);
    }
    return ret;
}

// test_resource_mgmt.c
#define _GNU_SOURCE
#include "resource_mgmt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Helper to create a temporary file with known content. */
static char *create_temp_config(const char *content) {
    char tmpl[] = "/tmp/rm_test_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        perror("mkstemp");
        return NULL;
    }

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        perror("fdopen");
        close(fd);
        unlink(tmpl);
        return NULL;
    }

    if (fwrite(content, 1, strlen(content), fp) != strlen(content)) {
        perror("fwrite");
        fclose(fp);
        unlink(tmpl);
        return NULL;
    }
    fflush(fp);
    fclose(fp);
    return strdup(tmpl);
}

/* Test harness demonstrating success and failure paths. */
int main(void) {
    config_t good_cfg;
    result_t res;
    char *temp_path = NULL;
    int rc;

    /* ---------- Successful execution ---------- */
    temp_path = create_temp_config("line1\nline2\nline3\n");
    if (!temp_path) {
        fprintf(stderr, "Failed to create temporary config file\n");
        return 1;
    }

    good_cfg.config_path = temp_path;
    good_cfg.max_lines = 5;   /* Allow all lines */

    rc = implementation_structure_and_resource_management(&good_cfg, &res);
    if (rc == RM_OK) {
        printf("Success: processed %d lines\nSummary:\n%s", res.processed_lines, res.summary);
    } else {
        fprintf(stderr, "Unexpected error code %d on success case\n", rc);
    }
    free_result(&res);
    unlink(temp_path);
    free(temp_path);
    temp_path = NULL;

    /* ---------- Injected failure: NULL config ---------- */
    rc = implementation_structure_and_resource_management(NULL, &res);
    if (rc != RM_OK) {
        printf("Correctly detected NULL config, error code: %d\n", rc);
    } else {
        fprintf(stderr, "Error: expected failure on NULL config\n");
    }

    /* ---------- Injected failure: non‑existent file ---------- */
    config_t bad_cfg;
    bad_cfg.config_path = "/nonexistent/path.cfg";
    bad_cfg.max_lines = 0;

    rc = implementation_structure_and_resource_management(&bad_cfg, &res);
    if (rc != RM_OK) {
        printf("Correctly detected file open error, error code: %d\n", rc);
    } else {
        fprintf(stderr, "Error: expected failure on bad file path\n");
        free_result(&res);
    }

    return 0;
}