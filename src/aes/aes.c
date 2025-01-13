#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/aes.h"
#include "../../include/aes_const.h"
typedef unsigned char byte;
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
