void cli_key (cli_ctx_t *cli_ctx) {
    // KEY
    printf("Enter the key:");
    // TODO: key input
    putchar('\n');

    #ifdef VERBOSE
    printf("Your key: ");
    for (int i = 0; i < CHUNK; i++) {
        printf("%02x", cli_ctx->key[i]);
    }
    putchar('\n');
    #endif // VERBOSE
}
