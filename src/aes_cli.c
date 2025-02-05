#include <ncurses.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include "../include/aes_cli.h"
#include "../include/aes.h"

#define CTR_CHUNK 8

static void aes_help(void);
static void cli_mode (cli_ctx_t *cli_ctx, char *mode);
static void cli_action (cli_ctx_t *cli_ctx, char *act);
static void cli_file (cli_ctx_t *cli_ctx, char *path);
static void cli_key (cli_ctx_t *cli_ctx);
static void cli_aes_init (cli_ctx_t *cli_ctx);
static void read_chunk (FILE *path, uint8_t *buffer, int pos, int amount);
static void write_chunk (FILE *path, uint8_t *buffer, int pos, int amount);
static void xor_chunk (uint8_t *dst, uint8_t *src);
static void copy_chunk (uint8_t *dst, uint8_t *src);
static void enter_iv (uint8_t *iv);
static void aes_ecb (cli_ctx_t *cli_ctx, aes_ctx *ctx, uint8_t *buffer, int file_len);
static void aes_cbc (cli_ctx_t *cli_ctx, aes_ctx *ctx, uint8_t *buffer, int file_len);
static void aes_cfb (cli_ctx_t *cli_ctx, aes_ctx *ctx, uint8_t *buffer, int file_len);
static void aes_ofb (cli_ctx_t *cli_ctx, aes_ctx *ctx, uint8_t *buffer, int file_len);
static void aes_ctr (cli_ctx_t *cli_ctx, aes_ctx *ctx, uint8_t *buffer, int file_len);

void aes_cli (int argc, char** argv) {
    /* handle input
    TODO add secription */

    // CONTEXT INITIALIZATION
    uint8_t key[CHUNK] = {0};
    FILE *file_path = NULL;
    cli_ctx_t cli_ctx = {ECB, ENCRYPT, key, file_path};

    const char arg_help[] = "help";
    if (argc == 2) {
        if (strcmp(arg_help, argv[1]) == 0) aes_help();
        else printf("Invalid input. Try typing \"aes help\"\n");
        fclose(file_path);
        return;
    }

    if (argc == 3) {
        printf("Missing argument(s)\n");
        fclose(file_path);
        return;
    }

    cli_mode(&cli_ctx, argv[1]);     // MODE SELECTION
    cli_action(&cli_ctx, argv[2]);   // ACTION
    cli_file(&cli_ctx, argv[3]);     // FILE PATH
    cli_key(&cli_ctx);               // KEY
    cli_aes_init(&cli_ctx);          // ACTUAL ENCRYPTION/DECRYPTION

    fclose(file_path);
}

static void aes_help(void) {
    // TODO: add help page
}

static void cli_mode (cli_ctx_t *cli_ctx, char *mode) {
    // MODE SELECTION
    const char option_cbc[] = "cbc";
    const char option_ofb[] = "ofb";
    const char option_cfb[] = "cfb";
    const char option_ctr[] = "ctr";

    // ECB is default option
    if (strcmp(mode, option_cbc) == 0) cli_ctx->mode = CBC;
    if (strcmp(mode, option_ofb) == 0) cli_ctx->mode = OFB;
    if (strcmp(mode, option_cfb) == 0) cli_ctx->mode = CFB;
    if (strcmp(mode, option_ctr) == 0) cli_ctx->mode = CTR;

    #ifdef VERBOSE
    printf("Selected mode: ");
    switch (cli_ctx->mode) {
    case CBC:
        printf("%s\n", option_cbc);
        break;
    case OFB:
        printf("%s\n", option_ofb);
        break;
    case CFB:
        printf("%s\n", option_cfb);
        break;
    case CTR:
        printf("%s\n", option_ctr);
        break;
    default:
        printf("ecb\n");
        break;
    }
    #endif // VERBOSE
}

static void cli_action (cli_ctx_t *cli_ctx, char *act) {
    // SELECT ACTION
    const char option_decrypt[] = "decrypt";
    // TODO: "-e" and "-d" options
    // ENCRYPT is default action
    if (strcmp(act, option_decrypt) == 0) cli_ctx->action = DECRYPT;

    #ifdef VERBOSE
    printf("Selected action: ");
    switch (cli_ctx->action) {
    case DECRYPT:
        printf("decrypt file\n");
        break;
    default:
        printf("encrypt file\n");
        break;
    }
    #endif // VERBOSE
}

static void cli_file (cli_ctx_t *cli_ctx, char *path) {
    // FILE PATH
    cli_ctx->path = fopen(path, "r+b");

    // TODO: error when it's impossible to open the file
  
    #ifdef VERBOSE
    if (cli_ctx->path) printf("File was opened successfully\n");
    printf("Path to the file: %s", path);
    putchar('\n');
    #endif // VERBOSE
}

static void cli_key (cli_ctx_t *cli_ctx) {
    // KEY
    uint8_t ch = 0;
    printf("Enter the key: ");
    for (int i = 0; i < CHUNK; i++) {
        ch = getchar();
        if (ch == '\n') break;
        cli_ctx->key[i] = ch;
    }

    #ifdef VERBOSE
    printf("Your key: ");
    for (int i = 0; i < CHUNK; i++) {
        printf("%02x", cli_ctx->key[i]);
    }
    putchar('\n');
    #endif // VERBOSE
}

static void cli_aes_init (cli_ctx_t *cli_ctx) {
    // interface to interract with aes.c
    uint8_t buffer[CHUNK] = {0};
    aes_ctx ctx;
    aes_init_ctx(&ctx, AES_128, cli_ctx->key);
    
    // file lenght & exceptions
    int file_len = 0;
    fseek(cli_ctx->path, 0, SEEK_END);
    file_len = ftell(cli_ctx->path);
    fseek(cli_ctx->path, 0, SEEK_SET);
    
    if (file_len == 0) {
        // TODO: add VERBOSE
        aes_free_ctx(&ctx);
        return;
    }
    file_len -= 1; // prevent EOF reading
    
    #ifdef VERBOSE
    printf("File lenght: %d\n", file_len);
    #endif // VERBOSE

    switch (cli_ctx->mode) {
    case CBC:
        aes_cbc(cli_ctx, &ctx, buffer, file_len);
        break;
    case OFB:
        aes_ofb(cli_ctx, &ctx, buffer, file_len);
        break;
    case CFB:
        aes_cfb(cli_ctx, &ctx, buffer, file_len);
        break;
    case CTR:
        aes_ctr(cli_ctx, &ctx, buffer, file_len);
        break;
    default:
        aes_ecb(cli_ctx, &ctx, buffer, file_len);
        break;
    }
    
    aes_free_ctx(&ctx);
}

static void read_chunk (FILE *path, uint8_t *buffer, int pos, int amount) {
    fseek(path, pos, SEEK_SET);
    fread(buffer, sizeof(uint8_t), amount, path);
    for (int i = amount; i < CHUNK; buffer[i++] = 0); // padding
}

static void write_chunk (FILE *path, uint8_t *buffer, int pos, int amount) {
    fseek(path, pos, SEEK_SET);
    fwrite(buffer, sizeof(uint8_t), amount, path);
}

static void xor_chunk (uint8_t *dst, uint8_t *src) {
    for (int i = 0; i < CHUNK; i++) {
        dst[i] = dst[i] ^ src[i];
    }
}

static void copy_chunk (uint8_t *dst, uint8_t *src) {
    for (int i = 0; i < CHUNK; i++) {
        dst[i] = src[i];
    }
}

static void enter_iv (uint8_t *iv) {
    uint8_t ch = 0;
    printf("Enter initialization vector: ");
    for (int i = 0; i < CHUNK; i++) {
        ch = getchar();
        if (ch == '\n') break;
        iv[i] = ch;
    }
    
    #ifdef VERBOSE
    printf("Initialization vector: ");
    for (int i = 0; i < CHUNK; i++) {
        printf("%02x", iv[i]);
    }
    putchar('\n');
    #endif // VERBOSE 
}

static void aes_ecb (cli_ctx_t *cli_ctx, aes_ctx *ctx, uint8_t *buffer, int file_len) {
    #ifdef VERBOSE
    printf("File content: ");
    #endif // VERBOSE
    
    int position = 0;
    int amount = 0;
    for (int i = 0; i <= file_len/CHUNK; i++) {
        position = i * CHUNK;
        if ((file_len - position) == 0) break; // prevent unnecessary padding when EOF reached
        
        // writing current chunk from fule to buffer
        amount = ((file_len - position) >= CHUNK) ? CHUNK : file_len - position; // chunk padding
        read_chunk(cli_ctx->path, buffer, position, amount);
        
        // file preview
        #ifdef VERBOSE
        printf("\nCurrent chunk: ");
        for (int j = 0; j < CHUNK; j++) {
            printf("%02x", buffer[j]);
        }
        #endif // VERBOSE
          
        // actual encryption / decryption
        if (cli_ctx->action == ENCRYPT) aes_encrypt(ctx, buffer, CHUNK);
        if (cli_ctx->action == DECRYPT) aes_decrypt(ctx, buffer, CHUNK);
        
        // writing current chunk from buffer to file
        write_chunk(cli_ctx->path, buffer, position, amount);
    }
    
    #ifdef VERBOSE
    putchar('\n');
    #endif // VERBOSE 
}

static void aes_cbc (cli_ctx_t *cli_ctx, aes_ctx *ctx, uint8_t *buffer, int file_len) {
    uint8_t tmp[CHUNK] = {0};
    uint8_t iv[CHUNK] = {0}; // initialization vector
    
    enter_iv(iv);
    
    #ifdef VERBOSE
    printf("File content: ");
    #endif // VERBOSE
    
    copy_chunk(tmp, iv);
    
    int position = 0;
    int amount = 0;
    for (int i = 0; i <= file_len/CHUNK; i++) {
        position = i * CHUNK;
        if ((file_len - position) == 0) break; // prevent unnecessary padding when EOF reached
        
        // writing current chunk from fule to buffer
        amount = ((file_len - position) >= CHUNK) ? CHUNK : file_len - position; // chunk padding
        read_chunk(cli_ctx->path, buffer, position, amount);
        
        // file preview
        #ifdef VERBOSE
        printf("\nCurrent chunk: ");
        for (int j = 0; j < CHUNK; j++) {
            printf("%02x", buffer[j]);
        }
        #endif // VERBOSE
          
        // actual encryption / decryption
        if (cli_ctx->action == ENCRYPT) {
            xor_chunk(buffer, iv);
            aes_encrypt(ctx, buffer, CHUNK);
            copy_chunk(iv, buffer);
        }
        if (cli_ctx->action == DECRYPT) {
            copy_chunk(tmp, buffer);
            aes_decrypt(ctx, buffer, CHUNK);
            xor_chunk(buffer, iv);
            copy_chunk(iv, tmp);
        }
        
        // writing current chunk from buffer to file
        write_chunk(cli_ctx->path, buffer, position, amount);
    }
    
    #ifdef VERBOSE
    putchar('\n');
    #endif // VERBOSE 
}

static void aes_cfb (cli_ctx_t *cli_ctx, aes_ctx *ctx, uint8_t *buffer, int file_len) {
    uint8_t tmp[CHUNK] = {0};
    uint8_t iv[CHUNK] = {0}; // initialization vector
    
    enter_iv(iv);
    
    #ifdef VERBOSE
    printf("File content: ");
    #endif // VERBOSE
    
    int position = 0;
    int amount = 0;
    for (int i = 0; i <= file_len/CHUNK; i++) {
        position = i * CHUNK;
        if ((file_len - position) == 0) break; // prevent unnecessary padding when EOF reached
        
        // writing current chunk from fule to buffer
        amount = ((file_len - position) >= CHUNK) ? CHUNK : file_len - position; // chunk padding
        read_chunk(cli_ctx->path, buffer, position, amount);
        
        // file preview
        #ifdef VERBOSE
        printf("\nCurrent chunk: ");
        for (int j = 0; j < CHUNK; j++) {
            printf("%02x", buffer[j]);
        }
        #endif // VERBOSE
          
        // actual encryption / decryption
        aes_encrypt(ctx, iv, CHUNK);
        if (cli_ctx->action == ENCRYPT) {
            xor_chunk(buffer, iv);
            copy_chunk(iv, buffer);
        }
        if (cli_ctx->action == DECRYPT) {
            copy_chunk(tmp, buffer);
            xor_chunk(buffer, iv);
            copy_chunk(iv, tmp);
        }
        
        // writing current chunk from buffer to file
        write_chunk(cli_ctx->path, buffer, position, amount);
    }
    
    #ifdef VERBOSE
    putchar('\n');
    #endif // VERBOSE 
}

static void aes_ofb (cli_ctx_t *cli_ctx, aes_ctx *ctx, uint8_t *buffer, int file_len) {
    uint8_t iv[CHUNK] = {0}; // initialization vector
    
    enter_iv(iv);
    
    #ifdef VERBOSE
    printf("File content: ");
    #endif // VERBOSE
    
    int position = 0;
    int amount = 0;
    for (int i = 0; i <= file_len/CHUNK; i++) {
        position = i * CHUNK;
        if ((file_len - position) == 0) break; // prevent unnecessary padding when EOF reached
        
        // writing current chunk from fule to buffer
        amount = ((file_len - position) >= CHUNK) ? CHUNK : file_len - position; // chunk padding
        read_chunk(cli_ctx->path, buffer, position, amount);
        
        // file preview
        #ifdef VERBOSE
        printf("\nCurrent chunk: ");
        for (int j = 0; j < CHUNK; j++) {
            printf("%02x", buffer[j]);
        }
        #endif // VERBOSE
          
        // actual encryption / decryption
        aes_encrypt(ctx, iv, CHUNK);
        xor_chunk(buffer, iv);
        
        // writing current chunk from buffer to file
        write_chunk(cli_ctx->path, buffer, position, amount);
    }
    
    #ifdef VERBOSE
    putchar('\n');
    #endif // VERBOSE 
}

static void aes_ctr (cli_ctx_t *cli_ctx, aes_ctx *ctx, uint8_t *buffer, int file_len) {
    uint8_t tmp[CHUNK] = {0}; // initialization vector
    union cast_t { uint64_t cast64; uint8_t cast8[CTR_CHUNK]; } cast;
    
    uint64_t nonce = 0;
    uint64_t ctr = 0;
    
    printf("Enter nonce: ");
    scanf("%"SCNx64, &nonce);
    
    #ifdef VERBOSE
    printf("Nonce: %"PRIx64"\n", nonce);
    #endif // VERBOSE
    
    cast.cast64 = nonce;
    for (int i = 0; i < CTR_CHUNK; i++) {
        tmp[i] = cast.cast8[i];
    }
    
    #ifdef VERBOSE
    printf("File content: ");
    #endif // VERBOSE
    
    int position = 0;
    int amount = 0;
    for (int i = 0; i <= file_len/CHUNK; i++) {
        position = i * CHUNK;
        if ((file_len - position) == 0) break; // prevent unnecessary padding when EOF reached
        
        // writing current chunk from fule to buffer
        amount = ((file_len - position) >= CHUNK) ? CHUNK : file_len - position; // chunk padding
        read_chunk(cli_ctx->path, buffer, position, amount);
        
        // file preview
        #ifdef VERBOSE
        printf("\nCurrent chunk: ");
        for (int j = 0; j < CHUNK; j++) {
            printf("%02x", buffer[j]);
        }
        #endif // VERBOSE
          
        // actual encryption / decryption
        aes_encrypt(ctx, tmp, CHUNK);
        xor_chunk(buffer, tmp);
        
        // update counter 
        ctr += 1;
        cast.cast64 = ctr;
        for (int i = 0; i < CTR_CHUNK; i++) {
            tmp[CTR_CHUNK + i] = cast.cast8[i];
        }
        
        // writing current chunk from buffer to file
        write_chunk(cli_ctx->path, buffer, position, amount);
    }
    
    #ifdef VERBOSE
    putchar('\n');
    #endif // VERBOSE 
}
