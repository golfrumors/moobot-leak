#pragma once

#include <stdint.h>

#include "util.h"

#define PHI 0x9e3779b9

void rand_seed(void);
uint32_t rand_real(void);
void rand_packet(char *, int);
void rand_alphastr(uint8_t *, int);
