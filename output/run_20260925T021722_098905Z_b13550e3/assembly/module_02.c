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
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

 
typedef struct RecordInfo {
    char *transaction_id;  
    double amount;         
    char *timestamp;       
} RecordInfo;

 
typedef struct ExecutionResult {
    int total_files_processed;  
    int total_records_found;    
    RecordInfo *records;        
    char *error_message;        
} ExecutionResult;

 
void free_execution_result(ExecutionResult *result);

 
static int parse_record_line(const char *line, RecordInfo *rec);

 
ExecutionResult *execution_environment_and_data_handling(char *file_paths[], int file_count)
{
    ExecutionResult *result = calloc(1, sizeof(ExecutionResult));
    if (!result) {
         
        return NULL;
    }

     
    size_t records_capacity = 64;
    result->records = malloc(records_capacity * sizeof(RecordInfo));
    if (!result->records) {
        result->error_message = strdup("Memory allocation failed for records array");
        return result;
    }

    for (int i = 0; i < file_count; ++i) {
        const char *path = file_paths[i];
        struct stat st_before, st_after;

        if (stat(path, &st_before) != 0) {
            result->error_message = malloc(256);
            if (result->error_message) {
                snprintf(result->error_message, 256,
                         "Cannot stat file \"%s\": %s", path, strerror(errno));
            }
            break;
        }

        FILE *fp = fopen(path, "r");
        if (!fp) {
            result->error_message = malloc(256);
            if (result->error_message) {
                snprintf(result->error_message, 256,
                         "Failed to open file \"%s\" for reading: %s", path, strerror(errno));
            }
            break;
        }

        char *line = NULL;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&line, &len, fp)) != -1) {
             
            if (read > 0 && line[read - 1] == '\n')
                line[read - 1] = '\0';

            RecordInfo rec = {0};
            if (parse_record_line(line, &rec) != 0) {
                result->error_message = strdup("Invalid record format encountered");
                free(line);
                fclose(fp);
                 
                for (int j = 0; j < result->total_records_found; ++j) {
                    free(result->records[j].transaction_id);
                    free(result->records[j].timestamp);
                }
                free(result->records);
                return result;
            }

             
            if ((size_t)result->total_records_found >= records_capacity) {
                records_capacity *= 2;
                RecordInfo *tmp = realloc(result->records,
                                          records_capacity * sizeof(RecordInfo));
                if (!tmp) {
                    result->error_message = strdup("Memory allocation failed while expanding records array");
                    free(line);
                    fclose(fp);
                     
                    for (int j = 0; j < result->total_records_found; ++j) {
                        free(result->records[j].transaction_id);
                        free(result->records[j].timestamp);
                    }
                    free(result->records);
                    return result;
                }
                result->records = tmp;
            }

            result->records[result->total_records_found++] = rec;
        }

        free(line);
        fclose(fp);

        if (stat(path, &st_after) != 0) {
            result->error_message = malloc(256);
            if (result->error_message) {
                snprintf(result->error_message, 256,
                         "Cannot stat file after processing \"%s\": %s", path, strerror(errno));
            }
            break;
        }

         
        if (st_before.st_mode != st_after.st_mode ||
            st_before.st_uid  != st_after.st_uid  ||
            st_before.st_gid  != st_after.st_gid  ||
            st_before.st_mtim.tv_sec != st_after.st_mtim.tv_sec ||
            st_before.st_mtim.tv_nsec != st_after.st_mtim.tv_nsec ||
            st_before.st_atim.tv_sec != st_after.st_atim.tv_sec ||
            st_before.st_atim.tv_nsec != st_after.st_atim.tv_nsec) {
            result->error_message = strdup("File attributes changed during processing");
            break;
        }

        result->total_files_processed++;
    }

    return result;
}

 
static int parse_record_line(const char *line, RecordInfo *rec)
{
    if (!line || !rec)
        return -1;

    char *copy = strdup(line);
    if (!copy)
        return -1;

    char *saveptr = NULL;
    char *token = strtok_r(copy, ",", &saveptr);
    if (!token) {
        free(copy);
        return -1;
    }
    rec->transaction_id = strdup(token);
    if (!rec->transaction_id) {
        free(copy);
        return -1;
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (!token) {
        free(rec->transaction_id);
        free(copy);
        return -1;
    }
    char *endptr;
    rec->amount = strtod(token, &endptr);
    if (endptr == token) {
        free(rec->transaction_id);
        free(copy);
        return -1;
    }

    token = strtok_r(NULL, ",", &saveptr);
    if (!token) {
        free(rec->transaction_id);
        free(copy);
        return -1;
    }
    rec->timestamp = strdup(token);
    if (!rec->timestamp) {
        free(rec->transaction_id);
        free(copy);
        return -1;
    }

    free(copy);
    return 0;
}

 
void free_execution_result(ExecutionResult *result)
{
    if (!result)
        return;

    for (int i = 0; i < result->total_records_found; ++i) {
        free(result->records[i].transaction_id);
        free(result->records[i].timestamp);
    }
    free(result->records);
    free(result->error_message);
    free(result);
}