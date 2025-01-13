void cli_action (cli_ctx_t *cli_ctx, char *act) {
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
