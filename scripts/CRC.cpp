#include "stdio.h"
#include "string.h"
#include <iostream>

#define CRCPOLY  0x04C11DB7
#define INITXOR  0xFFFFFFFF
#define FINALXOR 0xFFFFFFFF

#define REFIN
#define REFOUT

#define MAX_PW_LENGTH 10
#define MAXBUFLEN 256

static unsigned int  crc_table[MAXBUFLEN];
static unsigned int  crc_revtable[MAXBUFLEN];


unsigned char reverse_bit_order(unsigned char a)
{
    unsigned int i;
    unsigned char b = 0;

    for (i = 0; i < 8; i++)
        b |= ((a >> (7 - i)) & 0x01) << i;
    return b;
}

unsigned int reverse_crc_order(unsigned int crcin)
{
    unsigned int temp[4];
    unsigned int crcout;
    unsigned int i;

    for (i = 0; i < 4; i++)
    {
        temp[i] = reverse_bit_order((crcin >> 8 * i) & 0xff);
    }
    crcout = (temp[0] << 24) | (temp[1] << 16) | (temp[2] << 8) | (temp[3] << 0);
    return crcout;

}

void make_crc_table()
{
    for (unsigned int byte = 0; byte <= 0xFF; byte++)
    {
        unsigned int  crc = (byte << 24);
        for (uint8_t bit = 0; bit < 8; bit++)
        {
            if (crc & 0x80000000u)
                crc = (crc << 1) ^ CRCPOLY;
            else
                crc = (crc << 1);
        }
        crc_table[byte] = crc;
    }
}

void make_crc_revtable()
{
    for (unsigned int  byte = 0; byte < 256; byte++)
    {
        unsigned int  crc = byte;
        for (uint8_t bit = 0; bit < 8; bit++)
        {
            if ((crc & 1) != 0)
                crc = (crc >> 1) ^ (CRCPOLY >> 1) ^ 0x80000000u;
            else
                crc >>= 1;
        }
        crc_revtable[byte] = crc;
    }
}


int crc32(uint8_t* buffer, size_t length)
{
    unsigned char temp;
    unsigned int  crcreg = INITXOR;

    for (size_t i = 0; i < length; ++i) {
#ifdef REFIN
        temp = reverse_bit_order(buffer[i]);
#else
        temp = buffer[i];
#endif
        crcreg = crc_table[(temp ^ (crcreg >> 24)) & 0xFF] ^ (crcreg << 8);
    }
    crcreg ^= FINALXOR;
#ifdef REFOUT
    crcreg = reverse_crc_order(crcreg);
#endif
    return crcreg;
}

unsigned int reverse_crc(unsigned char* buffer, int length, unsigned int crcinit)
{
    int i;
    unsigned int  crcreg;
    unsigned char temp;

#ifdef REFOUT
    crcinit = reverse_crc_order(crcinit);
#endif 

    crcreg = crcinit ^ FINALXOR;
    for (i = length - 1; i >= 0; i--) {
#ifdef REFIN
        temp = reverse_bit_order(buffer[i]);
#else
        temp = buffer[i];
#endif
        crcreg = crc_revtable[crcreg & 0xff] ^ (crcreg >> 8) ^ (((unsigned int)temp) << 24);
    }
    crcreg ^= FINALXOR;

#ifdef REFOUT
    crcreg = reverse_crc_order(crcreg);
#endif

    return crcreg;
}

unsigned int forward_crc(unsigned char* buffer, int length, unsigned int crcinit)
{
    int i;
    unsigned int  crcreg;
    unsigned char temp;

#ifdef REFOUT
    crcinit = reverse_crc_order(crcinit);
#endif
    crcreg = crcinit ^ FINALXOR;
    for (i = 0; i < length; i++) {
#ifdef REFIN
        temp = reverse_bit_order(buffer[i]);
#else
        temp = buffer[i];
#endif
        crcreg = crc_table[(temp ^ (crcreg >> 24)) & 0xff] ^ (crcreg << 8);
    }
    crcreg ^= FINALXOR;

#ifdef REFOUT
    crcreg = reverse_crc_order(crcreg);
#endif

    return crcreg;
}




int main()
{
    unsigned int i,l;
    unsigned int  crc;
    unsigned int crc_from_user, crc_pw_only, crc_new, challenge_int, crc_new_xor;

    make_crc_table();
    make_crc_revtable();
 
    const char ct1[] = "+0";
    char challenge_string[MAXBUFLEN];
    char challenge_string_plus[MAXBUFLEN];

#ifdef TEST
    const char password[] = "123456789";
    // first build the pw +0
    for (i = 0; i < strlen(password); i++)
        temp[i] = password[i];
    for (i = strlen(password); i < strlen(password) + strlen(ct1); i++)
        temp[i] = ct1[i- strlen(password)];
    l = strlen(password) + strlen(ct1);
    // calculate crc on that
    crc_from_user = crc32((unsigned char*)temp, l);
    
#else
    // put the CRC from webserver as unsigned integer
    printf("Enter the PW Token of user as int (from pwcrc file, first number after user): ");
    scanf_s("%u", &crc_from_user);
#endif

    printf("CRC of PW+0 = %08X\n", crc_from_user);

    // then reverse 2 steps (+0)
    crc_pw_only = reverse_crc((unsigned char*)ct1, strlen(ct1), crc_from_user);
    printf("CRC of PW only= %08X\n", crc_pw_only);
    printf("Now as signed integer (to copy in go): %d\n", (int)crc_pw_only);

    printf("END\n");

    return 0;
}
