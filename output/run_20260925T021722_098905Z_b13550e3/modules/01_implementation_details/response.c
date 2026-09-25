#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>

/* Public status enumeration */
typedef enum {
    IMPL_SUCCESS = 0,
    IMPL_ERR_INVALID_INPUT,
    IMPL_ERR_ALLOC_FAIL,
    IMPL_ERR_PROCESS_FAIL
} impl_status_t;

/* Transaction input structure */
typedef struct {
    char *transaction_id;   /* NULL‑terminated transaction identifier */
    char *currency;         /* NULL‑terminated three‑letter currency code */
    double amount;          /* Transaction amount in units of the currency */
} transaction_t;

/* Result output structure */
typedef struct {
    double fee;             /* Calculated fee */
    double total;           /* Amount + fee */
    char *status_msg;       /* NULL‑terminated status message (allocated) */
} result_t;

/* Forward declaration of internal helper for error messages */
static const char *impl_strerror(impl_status_t code);

/* Implementation of the public API */
impl_status_t implementation_details(const transaction_t *tx,
                                     size_t tx_size,
                                     result_t *out)
{
    impl_status_t status = IMPL_SUCCESS;
    char *status_msg = NULL;

    /* Validate input pointers */
    if (!tx || !out || tx_size < sizeof(*tx)) {
        status = IMPL_ERR_INVALID_INPUT;
        goto cleanup;
    }

    /* Validate transaction fields */
    if (!tx->transaction_id || tx->transaction_id[0] == '\0' ||
        !tx->currency || strlen(tx->currency) != 3 ||
        tx->amount <= 0.0) {
        status = IMPL_ERR_INVALID_INPUT;
        goto cleanup;
    }

    /* Perform simple fee calculation (2% of amount) */
    out->fee = tx->amount * 0.02;
    out->total = tx->amount + out->fee;

    /* Allocate status message */
    status_msg = (char *)malloc(4);   /* "OK" + terminating NUL */
    if (!status_msg) {
        status = IMPL_ERR_ALLOC_FAIL;
        goto cleanup;
    }
    strcpy(status_msg, "OK");
    out->status_msg = status_msg;
    status_msg = NULL;   /* Ownership transferred */

cleanup:
    if (status != IMPL_SUCCESS) {
        if (out) {
            out->fee = 0.0;
            out->total = 0.0;
            out->status_msg = NULL;
        }
        if (status_msg) {
            free(status_msg);
        }
    }
    return status;
}

/* Internal error string helper (non‑public) */
static const char *impl_strerror(impl_status_t code)
{
    switch (code) {
        case IMPL_SUCCESS:          return "Success";
        case IMPL_ERR_INVALID_INPUT:return "Invalid input";
        case IMPL_ERR_ALLOC_FAIL:   return "Memory allocation failed";
        case IMPL_ERR_PROCESS_FAIL: return "Processing failure";
        default:                    return "Unknown error";
    }
}