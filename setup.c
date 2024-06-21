#include "sss.h"
#include "randombytes.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>


#define KEY_SIZE 256  // For RSA-2048, 256 bytes is sufficient
#define NUM_SHARES 6
#define THRESHOLD 3
#define ETH_PRIVATE_KEY_SIZE 32

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

EVP_PKEY *createEVP_PKEYWithFilename(const char *filename, int public) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open file %s\n", filename);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (public) {
        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    } else {
        pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    }

    fclose(fp);
    if (pkey == NULL) {
        handle_errors();
    }

    return pkey;
}

int public_encrypt(unsigned char *data, int data_len, const char *filename, unsigned char **encrypted) {
    EVP_PKEY *pkey = createEVP_PKEYWithFilename(filename, 1);
    if (!pkey) return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        handle_errors();
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        handle_errors();
    }

    size_t out_len;
    if (EVP_PKEY_encrypt(ctx, NULL, &out_len, data, data_len) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        handle_errors();
    }

    *encrypted = malloc(out_len);
    if (*encrypted == NULL) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        fprintf(stderr, "Memory allocation error\n");
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, *encrypted, &out_len, data, data_len) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        free(*encrypted);
        handle_errors();
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return out_len;
}

int private_decrypt(unsigned char *enc_data, int data_len, const char *filename, unsigned char **decrypted) {
    EVP_PKEY *pkey = createEVP_PKEYWithFilename(filename, 0);
    if (!pkey) return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        handle_errors();
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        handle_errors();
    }

    size_t out_len;
    if (EVP_PKEY_decrypt(ctx, NULL, &out_len, enc_data, data_len) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        handle_errors();
    }

    *decrypted = malloc(out_len);
    if (*decrypted == NULL) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        fprintf(stderr, "Memory allocation error\n");
        return -1;
    }

    if (EVP_PKEY_decrypt(ctx, *decrypted, &out_len, enc_data, data_len) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        free(*decrypted);
        handle_errors();
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return out_len;
}

void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex) {
    static const char hex_digits[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        hex[2 * i] = hex_digits[(bytes[i] >> 4) & 0xF];
        hex[2 * i + 1] = hex_digits[bytes[i] & 0xF];
    }
    hex[2 * len] = '\0';
}

int encrypt_and_save_share(unsigned char *share, int share_len, const char *pub_key_filename, const char *output_filename) {
    unsigned char *encrypted = NULL;
    int encrypted_length = public_encrypt(share, share_len, pub_key_filename, &encrypted);
    if (encrypted_length == -1) {
        fprintf(stderr, "Encryption failed for %s\n", output_filename);
        return -1;
    }

    // Convert the encrypted data to a hexadecimal string
    char *hex_encrypted = malloc(2 * encrypted_length + 1);
    if (hex_encrypted == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        free(encrypted);
        return -1;
    }
    bytes_to_hex(encrypted, encrypted_length, hex_encrypted);

    FILE *file = fopen(output_filename, "w"); // Open in text mode
    if (file == NULL) {
        fprintf(stderr, "Unable to open file %s for writing\n", output_filename);
        free(encrypted);
        free(hex_encrypted);
        return -1;
    }

    // Write the hex string to the file
    fprintf(file, "%s", hex_encrypted);
    fclose(file);
    free(encrypted);
    free(hex_encrypted);

    return 0;
}

// Converts a hex string to a byte array
void hex_to_bytes(const char *hex, uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; i++) {
        sscanf(&hex[i * 2], "%2hhx", &bytes[i]);
    }
}

// Utility function to print data in hex
void print_hex(const char *label, const uint8_t *data, size_t length) {
    printf("%s", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <secret>\n", argv[0]);
        return 1;
    }

    uint8_t data[sss_MLEN], restored[sss_MLEN];
    sss_Share shares[NUM_SHARES];
    size_t idx;
    int tmp;

    // Copy the Ethereum private key (hex in bytes) into data
    hex_to_bytes(argv[1], data, ETH_PRIVATE_KEY_SIZE);

    // Split the secret into 6 shares (with a recombination threshold of 3)
    sss_create_shares(shares, data, NUM_SHARES, THRESHOLD);

    // Print the generated shares in hexadecimal format
    for (idx = 0; idx < NUM_SHARES; idx++) {
        printf("Share %zu: ", idx);
        for (size_t j = 0; j < sss_SHARE_LEN; j++) {
            printf("%02X", shares[idx][j]);  // Print each byte in hexadecimal
        }
        printf("\n");
    }

    tmp = sss_combine_shares(restored, shares, 3);
	assert(tmp == 0);
	assert(memcmp(restored, data, sss_MLEN) == 0);

    // Print the restored secret as a hexadecimal string
    printf("Restored Ethereum Private Key: ");
    print_hex("", restored, ETH_PRIVATE_KEY_SIZE);


    // Define public key filenames and corresponding output files
    const char *public_keys[NUM_SHARES] = {
        "public_keys/public_dio.pem",
        "public_keys/public_solal.pem",
        "public_keys/public_dro.pem",
        "public_keys/public_emanuel.pem",
        "public_keys/public_peter.pem",
        "public_keys/public_gonza.pem"
    };

    const char *output_files[NUM_SHARES] = {
        "shares/dio.txt",
        "shares/solal.txt",
        "shares/dro.txt",
        "shares/emanuel.txt",
        "shares/peter.txt",
        "shares/gonza.txt"
    };

    // Encrypt and save each share
    for (idx = 0; idx < NUM_SHARES; idx++) {
        if (encrypt_and_save_share(shares[idx], sss_SHARE_LEN, public_keys[idx], output_files[idx]) == -1) {
            fprintf(stderr, "Failed to encrypt and save share for %s\n", output_files[idx]);
            return 1;
        }
        printf("Encrypted and saved share %zu\n", idx);
    }

    return 0;
}
