#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    const char *filename;
    size_t filename_length;
    const void *file_content;
    size_t file_content_length;
    const void *system_config;
    size_t system_config_length;
} inspect_indicators_input;

#define INSPECT_INDICATOR_STATUS_NOTICE UINT32_C(0x01)
#define INSPECT_INDICATOR_BITCOIN_ADDRESS UINT32_C(0x02)
#define INSPECT_INDICATOR_INGEST_URL UINT32_C(0x04)
#define INSPECT_INDICATOR_SESSION_PATH UINT32_C(0x08)
#define INSPECT_INDICATOR_PROCESSED_SUFFIX UINT32_C(0x10)
#define INSPECT_INDICATOR_CRONTAB_REBOOT UINT32_C(0x20)

static int inspect_contains(const void *buffer, size_t buffer_length,
                            const char *needle, size_t needle_length)
{
    const unsigned char *bytes = (const unsigned char *)buffer;
    size_t i;

    if (buffer == NULL || needle_length == 0 || buffer_length < needle_length) {
        return 0;
    }

    for (i = 0; i <= buffer_length - needle_length; ++i) {
        if (memcmp(bytes + i, needle, needle_length) == 0) {
            return 1;
        }
    }
    return 0;
}

static int inspect_is_config_whitespace(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\v' || c == '\f' || c == '\r';
}

static int inspect_has_crontab_reboot(const void *buffer, size_t length)
{
    const unsigned char *bytes = (const unsigned char *)buffer;
    static const char token[] = "@reboot";
    const size_t token_length = sizeof(token) - 1;
    size_t line_start = 0;

    if (buffer == NULL || length == 0) {
        return 0;
    }

    while (line_start < length) {
        size_t line_end = line_start;
        size_t p;

        while (line_end < length && bytes[line_end] != '\n') {
            ++line_end;
        }

        p = line_start;
        while (p < line_end && inspect_is_config_whitespace(bytes[p])) {
            ++p;
        }

        if (p < line_end && bytes[p] != '#'
            && line_end - p >= token_length
            && memcmp(bytes + p, token, token_length) == 0
            && (p + token_length == line_end
                || inspect_is_config_whitespace(bytes[p + token_length]))) {
            return 1;
        }

        line_start = line_end < length ? line_end + 1 : length;
    }

    return 0;
}

 
uint32_t inspect_indicators(const inspect_indicators_input *input)
{
    static const char status_name[] = "#_STATUS_NOTICE_#.txt";
    static const char processed_suffix[] = ".PROCESSED";
    static const char bitcoin_address[] = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    static const char ingest_url[] = "http://10.254.19.73:8080/ingest";
    static const char session_path[] = "/tmp/.session.token";
    uint32_t result = 0;
    size_t status_name_length = sizeof(status_name) - 1;
    size_t suffix_length = sizeof(processed_suffix) - 1;

    if (input == NULL) {
        return 0;
    }

    if (input->filename != NULL && input->filename_length != 0) {
        if (input->filename_length == status_name_length
            && memcmp(input->filename, status_name, status_name_length) == 0) {
            result |= INSPECT_INDICATOR_STATUS_NOTICE;
        }

        if (input->filename_length >= suffix_length
            && memcmp(input->filename + input->filename_length - suffix_length,
                      processed_suffix, suffix_length) == 0) {
            result |= INSPECT_INDICATOR_PROCESSED_SUFFIX;
        }
    }

    if (inspect_contains(input->file_content, input->file_content_length,
                         bitcoin_address, sizeof(bitcoin_address) - 1)
        || inspect_contains(input->system_config, input->system_config_length,
                            bitcoin_address, sizeof(bitcoin_address) - 1)) {
        result |= INSPECT_INDICATOR_BITCOIN_ADDRESS;
    }

    if (inspect_contains(input->file_content, input->file_content_length,
                         ingest_url, sizeof(ingest_url) - 1)
        || inspect_contains(input->system_config, input->system_config_length,
                            ingest_url, sizeof(ingest_url) - 1)) {
        result |= INSPECT_INDICATOR_INGEST_URL;
    }

    if (inspect_contains(input->file_content, input->file_content_length,
                         session_path, sizeof(session_path) - 1)
        || inspect_contains(input->system_config, input->system_config_length,
                            session_path, sizeof(session_path) - 1)) {
        result |= INSPECT_INDICATOR_SESSION_PATH;
    }

    if (inspect_has_crontab_reboot(input->system_config,
                                   input->system_config_length)) {
        result |= INSPECT_INDICATOR_CRONTAB_REBOOT;
    }

    return result;
}