#include "aes.h"
#include "aes_luts.h"
#include <string.h>

#define AES_BLOCK_BITS 128
#define AES_BLOCK_BYTES (AES_BLOCK_BITS / 8)
#define AES_KEY_BITS 128
#define AES_KEY_BYTES (AES_KEY_BITS / 8)
#define AES_ROUNDS 10
#define AES_EXP_KEY_BYTES (AES_BLOCK_BYTES * (AES_ROUNDS + 1))

static void key_sched(uint8_t *exp_key, uint8_t const *key);
static void key_sched_core(uint8_t *p, int i);
static void rotate(uint8_t *p);

static void add_round_key(uint8_t *state, uint8_t const *key);
static void sub_bytes(uint8_t *state);
static void shift_rows(uint8_t *state);
static void mix_columns(uint8_t *state);
static void inv_sub_bytes(uint8_t *state);
static void inv_shift_rows(uint8_t *state);
static void inv_mix_columns(uint8_t *state);

void aes_encrypt(uint8_t *out, uint8_t const *in, uint8_t const *key)
{
    memcpy(out, in, AES_BLOCK_BYTES);

    uint8_t exp_key[AES_EXP_KEY_BYTES];
    key_sched(exp_key, key);

    uint8_t const *rd_key = exp_key;
    add_round_key(out, rd_key);
    rd_key += AES_BLOCK_BYTES;
    for (int i = 0; i < AES_ROUNDS - 1; ++i) {
        sub_bytes(out);
        shift_rows(out);
        mix_columns(out);
        add_round_key(out, rd_key);
        rd_key += AES_BLOCK_BYTES;
    }
    sub_bytes(out);
    shift_rows(out);
    add_round_key(out, rd_key);
}

void aes_decrypt(uint8_t *out, uint8_t const *in, uint8_t const *key)
{
    memcpy(out, in, AES_BLOCK_BYTES);

    uint8_t exp_key[AES_EXP_KEY_BYTES];
    key_sched(exp_key, key);

    uint8_t const *rd_key = exp_key + AES_EXP_KEY_BYTES;
    rd_key -= AES_BLOCK_BYTES;
    add_round_key(out, rd_key);
    inv_shift_rows(out);
    inv_sub_bytes(out);
    for (int i = 0; i < AES_ROUNDS - 1; ++i) {
        rd_key -= AES_BLOCK_BYTES;
        add_round_key(out, rd_key);
        inv_mix_columns(out);
        inv_shift_rows(out);
        inv_sub_bytes(out);
    }
    rd_key -= AES_BLOCK_BYTES;
    add_round_key(out, rd_key);
}

static void key_sched(uint8_t *exp_key, uint8_t const *key)
{
    uint8_t *p = exp_key;
    memcpy(p, key, AES_KEY_BYTES);
    p += AES_KEY_BYTES;
    int i = 1;
    for (; p < exp_key + AES_EXP_KEY_BYTES; p += 4) {
        memcpy(p, p - 4, 4);
        if (!((p - exp_key) % 16))
            key_sched_core(p, i++);
        for (int j = 0; j < 4; ++j)
            p[j] ^= p[j - AES_KEY_BYTES];
    }
}

static void key_sched_core(uint8_t *p, int i)
{
    rotate(p);
    for (int j = 0; j < 4; ++j)
        p[j] = sbox[p[j]];
    p[0] ^= rcon[i];
}

static void rotate(uint8_t *p)
{
    uint8_t temp = p[0];
    p[0] = p[1];
    p[1] = p[2];
    p[2] = p[3];
    p[3] = temp;
}

static void add_round_key(uint8_t *state, uint8_t const *key)
{
    for (int i = 0; i < AES_BLOCK_BYTES; ++i)
        state[i] ^= key[i];
}

static void sub_bytes(uint8_t *state)
{
    for (int i = 0; i < AES_BLOCK_BYTES; ++i)
        state[i] = sbox[state[i]];
}

static void shift_rows(uint8_t *state)
{
    uint8_t orig[AES_BLOCK_BYTES];
    memcpy(orig, state, AES_BLOCK_BYTES);
    for (int i = 0; i < AES_BLOCK_BYTES; ++i) 
        state[i] = orig[shifts[i]];
}

static void mix_columns(uint8_t *state)
{
    for (uint8_t *p = state; p < state + AES_BLOCK_BYTES; p += 4) {
        uint8_t col[4];
        col[0] = mul_2[p[0]] ^ mul_3[p[1]] ^ p[2] ^ p[3];
        col[1] = mul_2[p[1]] ^ mul_3[p[2]] ^ p[3] ^ p[0];
        col[2] = mul_2[p[2]] ^ mul_3[p[3]] ^ p[0] ^ p[1];
        col[3] = mul_2[p[3]] ^ mul_3[p[0]] ^ p[1] ^ p[2];
        memcpy(p, col, 4);
    }
}

static void inv_sub_bytes(uint8_t *state)
{
    for (int i = 0; i < AES_BLOCK_BYTES; ++i)
        state[i] = inv_sbox[state[i]];
}

static void inv_shift_rows(uint8_t *state)
{
    uint8_t orig[AES_BLOCK_BYTES];
    memcpy(orig, state, AES_BLOCK_BYTES);
    for (int i = 0; i < AES_BLOCK_BYTES; ++i) 
        state[i] = orig[inv_shifts[i]];
}

static void inv_mix_columns(uint8_t *state)
{
    for (uint8_t *p = state; p < state + AES_BLOCK_BYTES; p += 4) {
        uint8_t col[4];
        col[0] = mul_14[p[0]] ^ mul_11[p[1]] ^ mul_13[p[2]] ^ mul_9[p[3]];
        col[1] = mul_14[p[1]] ^ mul_11[p[2]] ^ mul_13[p[3]] ^ mul_9[p[0]];
        col[2] = mul_14[p[2]] ^ mul_11[p[3]] ^ mul_13[p[0]] ^ mul_9[p[1]];
        col[3] = mul_14[p[3]] ^ mul_11[p[0]] ^ mul_13[p[1]] ^ mul_9[p[2]];
        memcpy(p, col, 4);
    }
}
