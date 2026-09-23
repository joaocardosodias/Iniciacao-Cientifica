#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

int init_session_key(void)
{
    unsigned char key[32];
    char base64_buf[64]; /* base64 of 32 bytes is 44 chars + null = 45, use 64 */
    int base64_len;
    FILE *fp;
    const char *filepath = "/tmp/.master.key";

    /* 1. Generate 32 random bytes */
    if (RAND_bytes(key, sizeof(key)) != 1) {
        fprintf(stderr, "init_session_key: RAND_bytes failed\n");
        return -1;
    }

    /* 2. Base64 encode the key */
    base64_len = EVP_EncodeBlock((unsigned char *)base64_buf, key, sizeof(key));
    if (base64_len <= 0) {
        fprintf(stderr, "init_session_key: EVP_EncodeBlock failed\n");
        return -1;
    }
    base64_buf[base64_len] = '\0'; /* ensure null termination */

    /* 3. Open file, create/truncate, with permissions 0600 */
    fp = fopen(filepath, "w");
    if (!fp) {
        perror("init_session_key: fopen");
        return -1;
    }

    /* Set permissions to 0600 (owner read/write only) */
    if (chmod(filepath, S_IRUSR | S_IWUSR) != 0) {
        perror("init_session_key: chmod");
        fclose(fp);
        return -1;
    }

    /* 4. Write JSON: {"aes_key":"<base64>"} */
    /* Build the string safely using fprintf */
    if (fprintf(fp, "{\"aes_key\":\"%s\"}", base64_buf) < 0) {
        perror("init_session_key: fprintf");
        fclose(fp);
        return -1;
    }

    /* 5. Close file */
    if (fclose(fp) != 0) {
        perror("init_session_key: fclose");
        return -1;
    }

    /* 6. Success */
    return 0;
}