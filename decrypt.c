#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SSS_MLEN 64    // Adjust to the length of your Shamir shares

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

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int decrypt_and_print(const char *encrypted_file, const char *private_key_file) {
    // Read the encrypted file
    FILE *file = fopen(encrypted_file, "rb");
    if (file == NULL) {
        fprintf(stderr, "Unable to open file %s\n", encrypted_file);
        return -1;
    }

    // Get the file size
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate buffer and read file content
    unsigned char *encrypted_data = malloc(file_size);
    if (encrypted_data == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        fclose(file);
        return -1;
    }
    fread(encrypted_data, 1, file_size, file);
    fclose(file);

    // Decrypt the data
    unsigned char *decrypted = NULL;
    int decrypted_length = private_decrypt(encrypted_data, file_size, private_key_file, &decrypted);
    free(encrypted_data);
    if (decrypted_length == -1) {
        fprintf(stderr, "Decryption failed.\n");
        return -1;
    }

    // Print the decrypted message in hex
    printf("Decrypted message: ");
    print_hex(decrypted, decrypted_length);

    // Clean up
    free(decrypted);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <encrypted_file> <private_key_file>\n", argv[0]);
        return 1;
    }

    const char *encrypted_file = argv[1];
    const char *private_key_file = argv[2];

    if (decrypt_and_print(encrypted_file, private_key_file) != 0) {
        return 1;
    }

    return 0;
}
