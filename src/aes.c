#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/aes.h"

static const byte sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const byte rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const byte rcon[10] = {
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};

//typedef unsigned char byte;
typedef byte state[4][4];

#define FOR_EVERY_STATE_BYTE \
    for(int _r = 0, _c = 0, __i__ = 1; \
            __i__ <= 16; \
            _r = __i__ / 4, _c = __i__ % 4, __i__++)

// Key element by key pointer
// Returns byte * to key matrix element's address specified by row and column
// So we supply byte *key and get byte *element
#define KEBKP(key, _r, _c) \
    (&(((byte (*)[8][4])#key)[_r][_c]))


static void sub_bytes(state *state);
static void rsub_bytes(state *state);
static void shift_rows(state *state);
static void rshift_rows(state *state);
static void mix_columns(state *state);
static void rmix_columns(state *state);
static void add_round_key(state *state, byte *key, size_t round_number);
static void key_schedule(byte *key, byte *expanded_key, AES_TYPE type);
//static void print_state(state *state);


void aes_init_ctx(aes_ctx *ctx, AES_TYPE type, byte *key)
{
    ctx->type = type;
    ctx->key = (byte *)calloc(sizeof(byte), AES_KEY_BUFFER_LEN(ctx->type));
    key_schedule(key, ctx->key, type);
}

void aes_free_ctx(aes_ctx *ctx)
{
    free(ctx->key);
}

static void sub_bytes(state *state)
{
    FOR_EVERY_STATE_BYTE
    {
        (*state)[_r][_c] = sbox[(*state)[_r][_c]];
    }
    return;
}

static void rsub_bytes(state *state)
{
    FOR_EVERY_STATE_BYTE
    {
        (*state)[_r][_c] = rsbox[(*state)[_r][_c]];
    }
    return;
}

static void shift_rows(state *state)
{
    byte temp;

    // 2st row
    temp = (*state)[1][0];
    (*state)[1][0] = (*state)[1][1];
    (*state)[1][1] = (*state)[1][2];
    (*state)[1][2] = (*state)[1][3];
    (*state)[1][3] = temp;

    // 3rd row
    temp = (*state)[2][0];
    (*state)[2][0] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[2][1];
    (*state)[2][1] = (*state)[2][3];
    (*state)[2][3] = temp;

    // 4th row
    temp = (*state)[3][0];
    (*state)[3][0] = (*state)[3][3];
    (*state)[3][3] = (*state)[3][2];
    (*state)[3][2] = (*state)[3][1];
    (*state)[3][1] = temp;
}


static void rshift_rows(state *state)
{
    byte temp;

    // 2st row
    temp = (*state)[1][3];
    (*state)[1][3] = (*state)[1][2];
    (*state)[1][2] = (*state)[1][1];
    (*state)[1][1] = (*state)[1][0];
    (*state)[1][0] = temp;

    // 3rd row
    temp = (*state)[2][2];
    (*state)[2][2] = (*state)[2][0];
    (*state)[2][0] = temp;
    temp = (*state)[2][3];
    (*state)[2][3] = (*state)[2][1];
    (*state)[2][1] = temp;

    // 4th row
    temp = (*state)[3][3];
    (*state)[3][3] = (*state)[3][0];
    (*state)[3][0] = (*state)[3][1];
    (*state)[3][1] = (*state)[3][2];
    (*state)[3][2] = temp;
}

static void mix_columns(state *state)
{
    byte* r[4];
    for(int i = 0; i < 4; i++)
    {
        // compose r
        r[0] = &((*state)[0][i]);
        r[1] = &((*state)[1][i]);
        r[2] = &((*state)[2][i]);
        r[3] = &((*state)[3][i]);

        byte a[4];
        byte b[4];
        byte c;
        byte h;

        for(c = 0; c < 4; c++) {
            a[c] = *r[c];
            h = *r[c] & 0x80;
            b[c] = *r[c] << 1;
            if(h == 0x80)
                b[c] ^= 0x1b;
            }

        *r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
        *r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
        *r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
        *r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    }
}

static byte gmul(byte a, byte b)
{
    byte p = 0;
    byte counter;
    byte hi_bit_set;
    for (counter = 0; counter < 8; counter++)
    {
        if ((b & 1) == 1)
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void rmix_columns(state *state)
{
    byte* r[4];
    for(int i = 0; i < 4; i++)
    {
        byte c[4];
        r[0] = &((*state)[0][i]);
        r[1] = &((*state)[1][i]);
        r[2] = &((*state)[2][i]);
        r[3] = &((*state)[3][i]);

        c[0] = *r[0];
        c[1] = *r[1];
        c[2] = *r[2];
        c[3] = *r[3];

        *r[0] = gmul(c[0], 14) ^ gmul(c[3], 9) ^ gmul(c[2], 13) ^ gmul(c[1], 11);
        *r[1] = gmul(c[1], 14) ^ gmul(c[0], 9) ^ gmul(c[3], 13) ^ gmul(c[2], 11);
        *r[2] = gmul(c[2], 14) ^ gmul(c[1], 9) ^ gmul(c[0], 13) ^ gmul(c[3], 11);
        *r[3] = gmul(c[3], 14) ^ gmul(c[2], 9) ^ gmul(c[1], 13) ^ gmul(c[0], 11);
    }
}

static void add_round_key(state *state, byte *key, size_t round_number)
{
    key += 16 * round_number;
    FOR_EVERY_STATE_BYTE
    {
        (*state)[_r][_c] ^= (*(byte (*)[4][4])key)[_r][_c];
    }
}

static void key_schedule(byte *key, byte *expanded_key, AES_TYPE type)
{
    // Actual round key
    byte (*ark)[4][4] = (byte (*)[4][4])expanded_key;
    // Previous round key
    byte (*prk)[4][4] = (byte (*)[4][4])expanded_key;

    byte atemp[4];
    byte a[4];
    byte temp;
    size_t rcon_idx = 0;

    // Copy initial key to expanded key
    memcpy(expanded_key, key, AES_KEY_LEN(type));
    ark += 1;
    for(int i = 0; i < AES_ROUNDS(type); i++)
    {
        atemp[0] = (*(byte (*)[4][4])prk)[0][3];
        atemp[1] = (*(byte (*)[4][4])prk)[1][3];
        atemp[2] = (*(byte (*)[4][4])prk)[2][3];
        atemp[3] = (*(byte (*)[4][4])prk)[3][3];

        a[0] = (*(byte (*)[4][4])prk)[0][0];
        a[1] = (*(byte (*)[4][4])prk)[1][0];
        a[2] = (*(byte (*)[4][4])prk)[2][0];
        a[3] = (*(byte (*)[4][4])prk)[3][0];

        //RotWord
        temp = atemp[3];
        atemp[3] = atemp[0];
        atemp[0] = atemp[1];
        atemp[1] = atemp[2];
        atemp[2] = temp;

        //printf("%02x %02x %02x %02x\n", atemp[0], atemp[1], atemp[2], atemp[3]);

        atemp[0] = sbox[atemp[0]];
        atemp[1] = sbox[atemp[1]];
        atemp[2] = sbox[atemp[2]];
        atemp[3] = sbox[atemp[3]];

        //printf("atemp is:\n");
        //printf("%02x %02x %02x %02x\n", atemp[0], atemp[1], atemp[2], atemp[3]);
        //printf("\n");

        // XOR S-box
        a[0] ^= atemp[0];
        a[1] ^= atemp[1];
        a[2] ^= atemp[2];
        a[3] ^= atemp[3];

        if (type == AES_128)
        {
            rcon_idx = i;
        }
        else if (type == AES_192)
        {
            rcon_idx = i % 6;
        }
        else if (type == AES_256)
        {
            rcon_idx = i % 8;
        }

        a[0] ^= rcon[rcon_idx];

        (*(byte (*)[4][4])ark)[0][0] = a[0];
        (*(byte (*)[4][4])ark)[1][0] = a[1];
        (*(byte (*)[4][4])ark)[2][0] = a[2];
        (*(byte (*)[4][4])ark)[3][0] = a[3];
        //printf("A IS %02x %02x %02x %02x\n", a[0], a[1], a[2], a[3]);

        for(int i = 1; i < 4; i++)
        {

            a[0] = (*(byte (*)[4][4])ark)[0][i - 1];
            a[1] = (*(byte (*)[4][4])ark)[1][i - 1];
            a[2] = (*(byte (*)[4][4])ark)[2][i - 1];
            a[3] = (*(byte (*)[4][4])ark)[3][i - 1];
            atemp[0] = (*(byte (*)[4][4])prk)[0][i];
            atemp[1] = (*(byte (*)[4][4])prk)[1][i];
            atemp[2] = (*(byte (*)[4][4])prk)[2][i];
            atemp[3] = (*(byte (*)[4][4])prk)[3][i];

            //printf("ATEMP IN LOOP %02x %02x %02x %02x\n", atemp[0], atemp[1], atemp[2], atemp[3]);
            //printf("A IN LOOP %02x %02x %02x %02x\n", a[0], a[1], a[2], a[3]);

            atemp[0] ^= a[0];
            atemp[1] ^= a[1];
            atemp[2] ^= a[2];
            atemp[3] ^= a[3];


            (*(byte (*)[4][4])ark)[0][i] = atemp[0];
            (*(byte (*)[4][4])ark)[1][i] = atemp[1];
            (*(byte (*)[4][4])ark)[2][i] = atemp[2];
            (*(byte (*)[4][4])ark)[3][i] = atemp[3];
        }
        //printf("After everything\n");

        ark += 1;
        prk += 1;
    }
}
/*
static void print_state(state *state)
{
    for(int _r = 0; _r < 4; _r++)
    {
        for(int _c = 0; _c < 4; _c++)
        {
            // printf("%02x ", (*state)[_r][_c]);
            printf("%02x", (*state)[_r][_c]);
        }
        // printf("\n");
    }
    //printf("\n");
}
*/
void aes_encrypt(aes_ctx *ctx, byte *buffer, size_t buffer_size)
{
    //printf("Initiated aes_encrypt\nCurrent buffer:\n");
    //print_state((state *)buffer);
    add_round_key((state *)buffer, ctx->key, 0);
    //printf("First add round key\n");
    //print_state((state *)buffer);
    for(int i = 1; i < AES_ROUNDS(ctx->type); i++)
    {
        sub_bytes((state *)buffer);
        //printf("After SubBytes\n");
        //print_state((state *)buffer);
        shift_rows((state *)buffer);
        //printf("After ShiftRows\n");
        //print_state((state *)buffer);
        mix_columns((state *)buffer);
        //printf("After MixColumns\n");
        //print_state((state *)buffer);
        add_round_key((state *)buffer, ctx->key, i);
        //printf("After AddRoundKey\n");
        //print_state((state *)buffer);
    }

    sub_bytes((state *)buffer);
    //printf("After SubBytes\n");
    //print_state((state *)buffer);
    shift_rows((state *)buffer);
    //printf("After ShiftRows\n");
    //print_state((state *)buffer);
    add_round_key((state *)buffer, ctx->key, AES_ROUNDS(ctx->type));
    //printf("Finished aes_encrypt\nResult is:\n");
    //print_state((state *)buffer);

    return;
}

void aes_decrypt(aes_ctx *ctx, byte *buffer, size_t buffer_size)
{
    //printf("Initiated aes_decrypt\nCurrent buffer:\n");
    //print_state((state *)buffer);
    add_round_key((state *)buffer, ctx->key, AES_ROUNDS(ctx->type));
    rshift_rows((state *)buffer);
    //printf("After rShiftRows\n");
    //print_state((state *)buffer);
    rsub_bytes((state *)buffer);
    //printf("After rSubBytes\n");
    //print_state((state *)buffer);

    for(int i = AES_ROUNDS(ctx->type) - 1; i > 0; i--)
    {
        add_round_key((state *)buffer, ctx->key, i);
        rmix_columns((state *)buffer);
        rshift_rows((state *)buffer);
        rsub_bytes((state *)buffer);
    }

    add_round_key((state *)buffer, ctx->key, 0);

    //printf("Aes decrypt finished, result:\n");
    //print_state((state *)buffer);

    return;
}
/*
void aes_encrypt(unsigned char *buffer, unsigned char *key, size_t size)
{
    printf("initiated aes encrypt\n");
    print_state((state *)buffer);

    printf("subbytes\n");
    sub_bytes((state *)buffer);
    printf("after subbytes\n");
    print_state((state *)buffer);
    printf("rsubbytes\n");
    rsub_bytes((state *)buffer);
    printf("after rsubbytes\n");
    print_state((state *)buffer);

    shift_rows((state*)buffer);
    printf("after shiftrows\n");
    print_state((state *)buffer);

    printf("rshiftrows\n");
    //rshift_rows((state*)buffer);
    printf("after rshiftrows\n");
    print_state((state *)buffer);

    mix_columns((state *)buffer);
    printf("after mix_columns\n");
    print_state((state *)buffer);

    //rmix_columns((state *)buffer);
    //printf("after rmix_columns\n");
    //print_state((state *)buffer);

    printf("add round key\n");
    add_round_key((state *)buffer, key);
    print_state((state *)buffer);

    printf("key schedule\n");
    key_schedule(key, 1);
    print_state((state *)key);
    printf("key schedule 2222\n");
    key_schedule(key, 2);
    print_state((state *)key);
    for(int i = 3; i <= 10; i++)
        key_schedule(key, i);
    print_state((state *)key);
}
*/
