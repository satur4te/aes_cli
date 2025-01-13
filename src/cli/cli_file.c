void cli_file (cli_ctx_t *cli_ctx, char *path) {
    // FILE PATH
    if (path[0] == '/') {
        // specified path is direct
        // TODO: handle this case + case '~'
        printf("You tried to open file using direct path\n");
        return; // <- delete later
    }
    else {
        // specified path is local
        cli_ctx->path = fopen(path, "r+b");
    }
    // TODO: error when it's impossible to open the file
  
    #ifdef VERBOSE
    if (cli_ctx->path) printf("File was opened successfully\n");
    printf("Path to the file: %s", path);
    putchar('\n');
    #endif // VERBOSE
}
