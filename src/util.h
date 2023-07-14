#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <strings.h>


#define UUID_LEN     37

#define MAX_LOG_SIZE 119


enum log_level { DEBUG, INFORMATION, WARNING, ERROR };


bool is_integer(const char *);
int parse_int(const char *);
int number_len(size_t);
int generate_uuid(char *);

/* Logging */
void sol_log_init(const char *);
void sol_log_close(void);
void sol_log(int, const char *, ...);

/* Memory management */
void *sol_malloc(size_t);
void *sol_calloc(size_t, size_t);
void *sol_realloc(void *, size_t);
size_t malloc_size(void *);
void sol_free(void *);
char *sol_strdup(const char *);
char *remove_occur(char *, char);
char *append_string(char *, char *, size_t);

size_t memory_used(void);


#define log(...) sol_log( __VA_ARGS__ )
#define sol_debug(...) log(DEBUG, __VA_ARGS__)
#define sol_warning(...) log(WARNING, __VA_ARGS__)
#define sol_error(...) log(ERROR, __VA_ARGS__)
#define sol_info(...) log(INFORMATION, __VA_ARGS__)


#define STREQ(s1, s2, len) strncasecmp(s1, s2, len) == 0 ? true : false


#endif
