void cli_mode (cli_ctx_t *cli_ctx, char *mode) {
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
