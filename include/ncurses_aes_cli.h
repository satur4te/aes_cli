#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ncurses.h>

#define VERBOSE
#define CHUNK 16
#define INPUT_LEN 128

void aes_cli (int argc, char** argv);
void aes_help(void);
void cli_mode (cli_ctx_t *cli_ctx, char *mode);
void cli_action (cli_ctx_t *cli_ctx, char *act);
void cli_file (cli_ctx_t *cli_ctx, char *path);
void cli_key (cli_ctx_t *cli_ctx);
void cli_aes_init (cli_ctx_t *cli_ctx);
#include "../src/cli/aes_help.c"
#include "../src/cli/cli_mode.c"
#include "../src/cli/cli_action.c"
#include "../src/cli/cli_file.c"
#include "../src/cli/cli_key.c"
#include "../src/cli/cli_aes_init.c"

enum modes { ECB, CBC, OFB, CFB, CTR };
enum actions { ENCRYPT, DECRYPT };

typedef struct {
    int mode;
    int action;
    uint8_t *key;
    FILE *path;
} cli_ctx_t;

void aes_cli (int argc, char** argv) {
    /* handle input
    TODO add description */

    // COMMAND LINE INTERFACE INIT
    WINDOW *stdsrc;
    initscr();

    // CONTEXT INITIALIZATION
    uint8_t key[CHUNK] = {0};
    FILE *file_path = NULL;
    cli_ctx_t cli_ctx = {ECB, ENCRYPT, key, file_path};

    const char arg_help[] = "help";
    if (argc == 2) {
        if (strcmp(arg_help, argv[1]) == 0) aes_help();
        else {
            printw("Invalid input. Try typing \"aes help\"\n");
            refresh();
        }
        fclose(file_path);
        endwin();
        return;
    }

    if (argc == 3) {
        printw("Missing argument(s)\n");
        refresh();
        fclose(file_path);
        endwin();
        return;
    }

    cli_mode(cli_ctx, argv[1]);     // MODE SELECTION
    cli_action(cli_ctx, argv[2]);   // ACTION
    cli_file(cli_ctx, argv[3]);     // FILE PATH
    cli_key(cli_ctx);               // KEY
    cli_aes_init(cli_ctx);          // ACTUAL ENCRYPTION/DECRYPTION

    fclose(file_path);
    endwin();
}
