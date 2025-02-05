#ifndef _AES_CLI_H_
#define _AES_CLI_H_

#include <stdio.h>
#include <stdint.h>

#define VERBOSE
#define CHUNK 16
#define INPUT_LEN 128

enum modes { ECB, CBC, OFB, CFB, CTR };
enum actions { ENCRYPT, DECRYPT };

typedef struct {
    int mode;
    int action;
    uint8_t *key;
    FILE *path;
} cli_ctx_t;

void aes_cli (int argc, char** argv);
#endif // !_AES_CLI_H_
