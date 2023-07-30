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

    Block block;

    FILE* f = fopen("block.bin", "r");
    fread(&block, sizeof(Block), 1, f);
    fclose(f);

    unsigned char hash[32];

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (unsigned char*)&block, sizeof(Block));
    sha256_final(&ctx, hash);

    int difficulty = compute_difficulty(hash);

    printf("Found block:\n");
    printf("   message: '%s'\n", block.message);
    printf("   target difficulty: %d (number of 0 bits at start of hash)\n", block.target_difficulty);
    printf("   nonce: %ld\n", block.nonce);
    printf("   hash:");
    for (int i = 0; i < 32; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n\n");
    if (difficulty >= block.target_difficulty) {
        printf("Hash has %d 0 bits at start (it is valid!)\n", difficulty);
    } else {
        printf("Hash has %d 0 bits at start (it is INVALID!)\n", difficulty);
    }

    return 0;
}

