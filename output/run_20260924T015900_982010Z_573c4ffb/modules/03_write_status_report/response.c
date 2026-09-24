#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct processing_status {
    const char *cargo_id;       /* Identificador da carga; NULL significa indisponível. */
    const char *stage;           /* Etapa atual; NULL significa indisponível. */
    const char *state;           /* Estado informado pelo processamento; NULL significa indisponível. */
    int percent_complete;        /* 0–100, ou -1 se indisponível. */
    const char *updated_at;      /* Horário da atualização; NULL significa indisponível. */
};

/*
 * Escreve um objeto JSON seguido de '\n', com os campos disponíveis nesta
 * ordem: cargo_id, stage, state, percent_complete e updated_at. Strings são
 * escapadas conforme JSON. Campos de texto NULL são omitidos; strings vazias
 * e sequências que não sejam UTF-8 válido são rejeitadas. percent_complete
 * deve ser -1 (indisponível) ou estar entre 0 e 100.
 *
 * Retorna 0 em caso de sucesso; retorna -1 e define errno em caso de argumento
 * ou campo inválido (EINVAL), ou de falha de escrita (errno da operação, ou
 * EIO quando a operação não fornece um errno).
 */
static int
status_valid_utf8(const unsigned char *s)
{
    while (*s != '\0') {
        unsigned char c = *s++;

        if (c <= 0x7f)
            continue;

        if (c >= 0xc2 && c <= 0xdf) {
            if (s[0] < 0x80 || s[0] > 0xbf)
                return 0;
            s += 1;
            continue;
        }

        if (c == 0xe0) {
            if (s[0] < 0xa0 || s[0] > 0xbf ||
                s[1] < 0x80 || s[1] > 0xbf)
                return 0;
            s += 2;
            continue;
        }

        if ((c >= 0xe1 && c <= 0xec) || (c >= 0xee && c <= 0xef)) {
            if (s[0] < 0x80 || s[0] > 0xbf ||
                s[1] < 0x80 || s[1] > 0xbf)
                return 0;
            s += 2;
            continue;
        }

        if (c == 0xed) {
            if (s[0] < 0x80 || s[0] > 0x9f ||
                s[1] < 0x80 || s[1] > 0xbf)
                return 0;
            s += 2;
            continue;
        }

        if (c == 0xf0) {
            if (s[0] < 0x90 || s[0] > 0xbf ||
                s[1] < 0x80 || s[1] > 0xbf ||
                s[2] < 0x80 || s[2] > 0xbf)
                return 0;
            s += 3;
            continue;
        }

        if (c >= 0xf1 && c <= 0xf3) {
            if (s[0] < 0x80 || s[0] > 0xbf ||
                s[1] < 0x80 || s[1] > 0xbf ||
                s[2] < 0x80 || s[2] > 0xbf)
                return 0;
            s += 3;
            continue;
        }

        if (c == 0xf4) {
            if (s[0] < 0x80 || s[0] > 0x8f ||
                s[1] < 0x80 || s[1] > 0xbf ||
                s[2] < 0x80 || s[2] > 0xbf)
                return 0;
            s += 3;
            continue;
        }

        return 0;
    }

    return 1;
}

static int
status_valid_text(const char *text)
{
    return text == NULL ||
           (text[0] != '\0' &&
            status_valid_utf8((const unsigned char *)text));
}

static int
status_write_bytes(FILE *out, const char *bytes, size_t length)
{
    if (fwrite(bytes, 1, length, out) != length) {
        if (errno == 0)
            errno = EIO;
        return -1;
    }
    return 0;
}

static int
status_write_literal(FILE *out, const char *text)
{
    return status_write_bytes(out, text, strlen(text));
}

static int
status_write_json_string(FILE *out, const char *text)
{
    static const char hex[] = "0123456789abcdef";
    const unsigned char *p = (const unsigned char *)text;

    if (fputc('"', out) == EOF)
        goto write_error;

    while (*p != '\0') {
        unsigned char c = *p++;

        if (c == '"' || c == '\\') {
            if (fputc('\\', out) == EOF || fputc(c, out) == EOF)
                goto write_error;
        } else if (c < 0x20) {
            char escaped[6] = {
                '\\', 'u', '0', '0', hex[c >> 4], hex[c & 0x0f]
            };
            if (status_write_bytes(out, escaped, sizeof escaped) < 0)
                return -1;
        } else {
            if (fputc(c, out) == EOF)
                goto write_error;
        }
    }

    if (fputc('"', out) == EOF)
        goto write_error;
    return 0;

write_error:
    if (errno == 0)
        errno = EIO;
    return -1;
}

int
write_status_report(FILE *out, const struct processing_status *status)
{
    int first = 1;

    if (out == NULL || status == NULL ||
        !status_valid_text(status->cargo_id) ||
        !status_valid_text(status->stage) ||
        !status_valid_text(status->state) ||
        !status_valid_text(status->updated_at) ||
        status->percent_complete < -1 ||
        status->percent_complete > 100) {
        errno = EINVAL;
        return -1;
    }

#define WRITE_TEXT_FIELD(name, value)                                      \
    do {                                                                   \
        if ((value) != NULL) {                                             \
            if (!first && status_write_literal(out, ",") < 0)             \
                return -1;                                                \
            if (status_write_literal(out, "\"" name "\":") < 0 ||        \
                status_write_json_string(out, (value)) < 0)                \
                return -1;                                                \
            first = 0;                                                     \
        }                                                                  \
    } while (0)

    if (status_write_literal(out, "{") < 0)
        return -1;

    WRITE_TEXT_FIELD("cargo_id", status->cargo_id);
    WRITE_TEXT_FIELD("stage", status->stage);
    WRITE_TEXT_FIELD("state", status->state);

    if (status->percent_complete != -1) {
        if (!first && status_write_literal(out, ",") < 0)
            return -1;
        if (fprintf(out, "\"percent_complete\":%d",
                    status->percent_complete) < 0) {
            if (errno == 0)
                errno = EIO;
            return -1;
        }
        first = 0;
    }

    WRITE_TEXT_FIELD("updated_at", status->updated_at);

    if (status_write_literal(out, "}\n") < 0)
        return -1;

    if (fflush(out) == EOF) {
        if (errno == 0)
            errno = EIO;
        return -1;
    }

#undef WRITE_TEXT_FIELD
    return 0;
}

#ifdef WRITE_STATUS_REPORT_TEST
#include <assert.h>
#include <stdlib.h>

static ssize_t
status_test_failing_write(void *cookie, const char *buf, size_t size)
{
    (void)cookie;
    (void)buf;
    (void)size;
    errno = EIO;
    return -1;
}

static int
status_test_success(void)
{
    struct processing_status status = {
        .cargo_id = "C-17",
        .stage = "sorting",
        .state = "in_progress",
        .percent_complete = 42,
        .updated_at = "2025-01-02T03:04:05Z"
    };
    char *buffer = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&buffer, &length);
    int result;

    if (out == NULL)
        return 1;

    result = write_status_report(out, &status);
    if (fclose(out) != 0)
        result = -1;

    if (result != 0 ||
        strcmp(buffer,
               "{\"cargo_id\":\"C-17\",\"stage\":\"sorting\","
               "\"state\":\"in_progress\",\"percent_complete\":42,"
               "\"updated_at\":\"2025-01-02T03:04:05Z\"}\n") != 0) {
        free(buffer);
        return 1;
    }

    free(buffer);
    return 0;
}

static int
status_test_invalid_input(void)
{
    struct processing_status status = {
        .cargo_id = "C-17",
        .stage = NULL,
        .state = "in_progress",
        .percent_complete = 101,
        .updated_at = NULL
    };
    char *buffer = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&buffer, &length);
    int result;

    if (out == NULL)
        return 1;

    errno = 0;
    result = write_status_report(out, &status);
    if (result != -1 || errno != EINVAL) {
        fclose(out);
        free(buffer);
        return 1;
    }

    if (fclose(out) != 0) {
        free(buffer);
        return 1;
    }

    if (length != 0) {
        free(buffer);
        return 1;
    }
    free(buffer);

    errno = 0;
    if (write_status_report(NULL, &status) != -1 || errno != EINVAL)
        return 1;

    return 0;
}

static int
status_test_output_failure(void)
{
    cookie_io_functions_t functions = {
        .read = NULL,
        .write = status_test_failing_write,
        .seek = NULL,
        .close = NULL
    };
    FILE *out = fopencookie(NULL, "w", functions);
    struct processing_status status = {
        .cargo_id = "C-17",
        .stage = NULL,
        .state = NULL,
        .percent_complete = -1,
        .updated_at = NULL
    };
    int result;

    if (out == NULL)
        return 1;

    if (setvbuf(out, NULL, _IONBF, 0) != 0) {
        fclose(out);
        return 1;
    }

    errno = 0;
    result = write_status_report(out, &status);
    fclose(out);
    return result == -1 ? 0 : 1;
}

int
main(void)
{
    assert(status_test_success() == 0);
    assert(status_test_invalid_input() == 0);
    assert(status_test_output_failure() == 0);
    return 0;
}
#endif