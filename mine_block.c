#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sha256.h"

typedef struct {
    long nonce;
    int  target_difficulty; // number of 0 bits at the start of the hash
    char message[128];
} Block;

int compute_difficulty(const unsigned char* hash) {
    int difficulty = 0;
    for (int i = 0; i < 32; ++i) {
        unsigned char ch = hash[i];
        if (ch == 0) {
            difficulty += 8;
            continue;
        } else if ((ch & 0xfe) == 0) {
            difficulty += 7;
        } else if ((ch & 0xfc) == 0) {
            difficulty += 6;
        } else if ((ch & 0xf8) == 0) {
            difficulty += 5;
        } else if ((ch & 0xf0) == 0) {
            difficulty += 4;
        } else if ((ch & 0xe0) == 0) {
            difficulty += 3;
        } else if ((ch & 0xc0) == 0) {
            difficulty += 2;
        } else if ((ch & 0x80) == 0) {
            difficulty += 1;
        }
        break;
    }
    return difficulty;
}

int main(int argc, const char** argv) {

    if (argc != 3) {
        printf("./mine_block [message] [target_difficulty]");
        return 0;
    }

    Block block;
    memset(&block, 0, sizeof(Block));
    block.nonce = 0;
    block.target_difficulty = atoi(argv[2]);
    strcpy(block.message, argv[1]);

    unsigned char hash[32];

    struct timespec ts_before, ts_after;
    timespec_get(&ts_before, TIME_UTC);

    while (1) {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (unsigned char*)&block, sizeof(Block));
        sha256_final(&ctx, hash);

        if (compute_difficulty(hash) >= block.target_difficulty) break;
        block.nonce++;
    }

    timespec_get(&ts_after, TIME_UTC);

    double nsecs = (double)(ts_after.tv_nsec - ts_before.tv_nsec) / 1000000000.0;
    double secs  = (double)(ts_after.tv_sec - ts_before.tv_sec) + nsecs;

    printf("Our block has nonce %ld and message '%s'\n", block.nonce, block.message);
    printf("The hash for our block is:\n");
    for (int i = 0; i < 32; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    printf("It took us %f secs to compute, which works out to:\n", secs);
    printf("%f hashes per second\n", (double)block.nonce / secs);

    FILE* f = fopen("block.bin", "w");
    fwrite(&block, sizeof(Block), 1, f);
    fclose(f);

    return 0;
}

