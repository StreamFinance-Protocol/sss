#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_SIZE 256  // For RSA-2048, 256 bytes is sufficient

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

int main() {
    // Define the message to encrypt
    unsigned char *message = (unsigned char *)"Hello, world!";
    unsigned char *encrypted = NULL;
    unsigned char *decrypted = NULL;

    // Encrypt the message
    int encrypted_length = public_encrypt(message, strlen((char *)message), "public.pem", &encrypted);
    if (encrypted_length == -1) {
        fprintf(stderr, "Encryption failed.\n");
        return 1;
    }

    // Print the encrypted message in hex
    printf("Encrypted message: ");
    for (int i = 0; i < encrypted_length; i++) {
        printf("%02x", encrypted[i]);
    }
    printf("\n");

    // Decrypt the message
    int decrypted_length = private_decrypt(encrypted, encrypted_length, "private.pem", &decrypted);
    if (decrypted_length == -1) {
        fprintf(stderr, "Decryption failed.\n");
        free(encrypted);
        return 1;
    }

    // Null-terminate the decrypted string
    decrypted[decrypted_length] = '\0';

    // Print the decrypted message
    printf("Decrypted message: %s\n", decrypted);

    // Clean up
    free(encrypted);
    free(decrypted);

    return 0;
}
