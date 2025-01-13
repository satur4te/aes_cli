#include "../aes/aes.c"
void cli_aes_init (cli_ctx_t *cli_ctx) {
    uint8_t buffer[CHUNK] = {0};
    int file_len;
    fseek(cli_ctx->path, 0, SEEK_END);
    file_len = ftell(cli_ctx->path);
    fseek(cli_ctx->path, 0, SEEK_SET);
    // TODO: return without actions when file is empty
    
    #ifdef VERBOSE
    printf("File lenght: %d\n", file_len);
    printf("File content: ");
    #endif // VERBOSE
    
    int counter = 0;
    for (int i = 0; i <= file_len/CHUNK; i++) {
        // prevent unnecessary padding
        if (counter == file_len) break;
        // current chunk
        for (int j = 0; j < CHUNK; j++) {
            if (counter < file_len) buffer[j] = getc(cli_ctx->path);
            else buffer[j] = 0; // padding <- fix it later
            counter += 1;
        }
        
        #ifdef VERBOSE
        // FILE PREVIEW (delete later)
        printf("\nCurrent chunk: ");
        for (int j = 0; j < CHUNK; j++) {
            printf("%02x", buffer[j]);
        }
        #endif // VERBOSE

        // ACTUAL ENCRYPTION/DECRYPTION
    }
    putchar('\n');
}
