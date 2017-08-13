#include "aes.h"
#include "test.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST(tests) run_tests((tests), sizeof(tests) / sizeof(*tests))

static int run_tests(struct Test const *tests, size_t num_tests);

static void str2bin(uint8_t *bin, char const *str);
static void bin2str(char *str, uint8_t const *bin);

int main(void)
{
    int err = 0;

    puts("### ECBGFSbox128 ###\n");
    err |= TEST(gf_sbox);

    puts("### ECBKeySbox128 ###\n");
    err |= TEST(key_sbox);

    puts("### ECBVarKey128 ###\n");
    err |= TEST(var_key);

    puts("### ECBVarTxt128 ###\n");
    err |= TEST(var_txt);

    if (!err)
        puts("SUCCESS");
    else
        puts("FAILURE");
    return err;
}

static int run_tests(struct Test const *tests, size_t numtests) {
    int err = 0;
    uint8_t key[16];
    uint8_t plain[16];
    uint8_t cipher[16];
    char buf[33];

    puts("[ENCRYPT]\n");
    for (size_t i = 0; i < numtests; ++i) {
        str2bin(key, tests[i].key);
        str2bin(plain, tests[i].plain);
        aes_encrypt(cipher, plain, key);

        printf("COUNT = %ld\n", i);
        bin2str(buf, key);
        printf("KEY = %s\n", buf);
        bin2str(buf, plain);
        printf("PLAINTEXT = %s\n", buf);
        bin2str(buf, cipher);
        printf("CIPHERTEXT = %s\n", buf);
        if (strcmp(buf, tests[i].cipher)) {
            printf("EXPECTED = %s\n", tests[i].cipher);
            err = -1;
        }
        puts("");
    }

    puts("[DECRYPT]\n");
    for (size_t i = 0; i < numtests; ++i) {
        str2bin(key, tests[i].key);
        str2bin(cipher, tests[i].cipher);
        aes_decrypt(plain, cipher, key);

        printf("COUNT = %ld\n", i);
        bin2str(buf, key);
        printf("KEY = %s\n", buf);
        bin2str(buf, cipher);
        printf("CIPHERTEXT = %s\n", buf);
        bin2str(buf, plain);
        printf("PLAINTEXT = %s\n", buf);
        if (strcmp(buf, tests[i].plain)) {
            printf("EXPECTED = %s\n", tests[i].plain);
            err = -1;
        }
        puts("");
    }
    puts("");

    return err;
}

static void str2bin(uint8_t *bin, char const *str)
{
    for (; *str; str += 2)
        sscanf(str, "%2hhx", bin++);
}

static void bin2str(char *str, uint8_t const *bin)
{
    for (int i = str[32] = 0; i < 16; ++i, str += 2)
        sprintf(str, "%02hhx", bin[i]);
}
