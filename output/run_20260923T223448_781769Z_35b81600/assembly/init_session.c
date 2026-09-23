#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define KEY_SIZE 32
#define B64_OUT_SIZE (((KEY_SIZE + 2) / 3) * 4 + 1)

const uint8_t* init_session(void) {
    uint8_t *key = NULL;
    char b64buf[B64_OUT_SIZE];
    char jsonbuf[128];
    FILE *fp = NULL;
    int ret = 0;

    /* Allocate buffer for the 32-byte raw key */
    key = (uint8_t*)malloc(KEY_SIZE);
    if (!key) {
        return NULL;
    }

    /* Generate cryptographically secure random bytes */
    if (RAND_bytes(key, KEY_SIZE) != 1) {
        goto fail;
    }

    /* Base64 encode the key */
    ret = EVP_EncodeBlock((unsigned char*)b64buf, key, KEY_SIZE);
    if (ret <= 0) {
        goto fail;
    }
    /* b64buf is null-terminated by EVP_EncodeBlock */

    /* Build JSON string: {"aes_key":"<b64>"} */
    snprintf(jsonbuf, sizeof(jsonbuf), "{\"aes_key\":\"%s\"}", b64buf);

    /* Open /tmp/.master.key for writing (create/truncate) */
    fp = fopen("/tmp/.master.key", "w");
    if (!fp) {
        goto fail;
    }

    /* Write the JSON content */
    size_t json_len = strlen(jsonbuf);
    if (fwrite(jsonbuf, 1, json_len, fp) != json_len) {
        goto fail;
    }

    /* Set file permissions to 0600 (owner read/write only) */
    if (fchmod(fileno(fp), S_IRUSR | S_IWUSR) != 0) {
        goto fail;
    }

    /* Close file */
    if (fclose(fp) != 0) {
        fp = NULL;
        goto fail;
    }
    fp = NULL;

    /* Success: return the raw key (caller must free) */
    return key;

fail:
    /* Cleanup on failure */
    if (fp) {
        fclose(fp);
    }
    free(key);
    return NULL;
}