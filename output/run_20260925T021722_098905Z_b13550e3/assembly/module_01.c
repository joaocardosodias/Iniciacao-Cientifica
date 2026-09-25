#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>

 
typedef enum {
    IMPL_SUCCESS = 0,
    IMPL_ERR_INVALID_INPUT,
    IMPL_ERR_ALLOC_FAIL,
    IMPL_ERR_PROCESS_FAIL
} impl_status_t;

 
typedef struct {
    char *transaction_id;    
    char *currency;          
    double amount;           
} transaction_t;

 
typedef struct {
    double fee;              
    double total;            
    char *status_msg;        
} result_t;

 
static const char *impl_strerror(impl_status_t code);

 
impl_status_t implementation_details(const transaction_t *tx,
                                     size_t tx_size,
                                     result_t *out)
{
    impl_status_t status = IMPL_SUCCESS;
    char *status_msg = NULL;

     
    if (!tx || !out || tx_size < sizeof(*tx)) {
        status = IMPL_ERR_INVALID_INPUT;
        goto cleanup;
    }

     
    if (!tx->transaction_id || tx->transaction_id[0] == '\0' ||
        !tx->currency || strlen(tx->currency) != 3 ||
        tx->amount <= 0.0) {
        status = IMPL_ERR_INVALID_INPUT;
        goto cleanup;
    }

     
    out->fee = tx->amount * 0.02;
    out->total = tx->amount + out->fee;

     
    status_msg = (char *)malloc(4);    
    if (!status_msg) {
        status = IMPL_ERR_ALLOC_FAIL;
        goto cleanup;
    }
    strcpy(status_msg, "OK");
    out->status_msg = status_msg;
    status_msg = NULL;    

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