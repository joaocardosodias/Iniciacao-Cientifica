#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct { const char *filename; size_t filename_length; const void *file_content; size_t file_content_length; const void *system_config; size_t system_config_length; } inspect_indicators_input;
struct audit_finding { const char *matched_path; const char *indicator; const char *indicator_value; };

extern int f01(void) __asm__("scan_storage");
extern uint32_t f02(const inspect_indicators_input *input) __asm__("inspect_indicators");
extern int f03(const char *report_path, const struct audit_finding *findings, size_t count) __asm__("write_audit_report");

int main(int argc, char *argv[])
{
    int scan_result;
    uint32_t indicator_result;
    int report_result;
    inspect_indicators_input input;
    struct audit_finding finding;
    const struct audit_finding *findings = NULL;
    size_t finding_count = 0;
    int failed = 0;

    (void)argc;
    scan_result = f01();

    input.filename = argv[0];
    input.filename_length = strlen(argv[0]);
    input.file_content = &scan_result;
    input.file_content_length = sizeof(scan_result);
    input.system_config = NULL;
    input.system_config_length = 0;
    indicator_result = f02(&input);

    if (indicator_result != 0) {
        finding.matched_path = argv[0];
        finding.indicator = "indicators_detected";
        finding.indicator_value = "yes";
        findings = &finding;
        finding_count = 1;
    }

    report_result = f03(argv[0], findings, finding_count);

    if (scan_result < 0) {
        fprintf(stderr, "f01 failed\n");
        failed = 1;
    }
    if (report_result < 0) {
        perror("f03");
        failed = 1;
    }

    return failed;
}
