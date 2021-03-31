#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "rand.h"
#include "util.h"

static uint32_t x, y, z, w;

void rand_seed(void)
{
    x = time(NULL);
    y = getpid() ^ getppid();
    z = clock();
    w = z ^ y;
}

uint32_t rand_real(void)
{
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}

void rand_alphastr(uint8_t *str, int len)
{
    const char alphaset[] = "abcdefghijklmnopqrstuvw012345678";

    while (len > 0)
    {
        if (len >= sizeof (uint32_t))
        {
            int i;
            uint32_t entropy = rand_real();

            for (i = 0; i < sizeof (uint32_t); i++)
            {
                uint8_t tmp = entropy & 0xff;

                entropy = entropy >> 8;
                tmp = tmp >> 3;

                *str++ = alphaset[tmp];
            }
            len -= sizeof (uint32_t);
        }
        else
        {
            *str++ = rand_real() % (sizeof (alphaset));
            len--;
        }
    }
}

void rand_packet(char *str, int len)
{
    while (len > 0)
    {
        if (len >= 4)
        {
            *((uint32_t *)str) = rand_real();
            str += sizeof (uint32_t);
            len -= sizeof (uint32_t);
        }
        else if (len >= 2)
        {
            *((uint16_t *)str) = rand_real() & 0xFFFF;
            str += sizeof (uint16_t);
            len -= sizeof (uint16_t);
        }
        else
        {
            *str++ = rand_real() & 0xFF;
            len--;
        }
    }
}
