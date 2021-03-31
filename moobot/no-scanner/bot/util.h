#pragma once

#include <stdint.h>

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

int util_split(const char *, char, char ***);
int util_stristr(char *, int, char *);
char *util_fdgets(char *, int, int);
char *util_itoa(int, int, char *);
int util_atoi(char *, int);
void *util_memset(void *, int, size_t);
int util_setblocking(int, int);
int util_strlen(char *);
char *util_strcat(char *, const char *);
char *util_strstr(register char *, char *);
char util_strcmp(char *, char *);
int util_strcpy(char *, char *);
void util_memcpy(void *, void *, int);
uint32_t util_local_addr(void);
static inline int util_isupper(char);
static inline int util_isalpha(char);
static inline int util_isspace(char);
static inline int util_isdigit(char);
