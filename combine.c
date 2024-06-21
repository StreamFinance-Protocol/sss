#include "sss.h" // Include Shamir's Secret Sharing header
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define THRESHOLD 3 // Recombination threshold
#define ETH_PRIVATE_KEY_SIZE 32

// Converts a hex string to a byte array
void hex_to_bytes(const char *hex, uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; i++) {
        sscanf(&hex[i * 2], "%2hhx", &bytes[i]);
    }
}

// Prints byte array in hex format
void print_hex(const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

// Utility function to print data in hex
char* get_hex_key(const uint8_t *data, size_t length) {

    // Allocate memory for the hex string (2 characters per byte + null terminator)
    char *hex_str = (char *)malloc((length * 2 + 1) * sizeof(char));
    if (!hex_str) {
        return NULL; // Allocation failed
    }

    // Convert each byte to hex and store in the string
    for (size_t i = 0; i < length; i++) {
        sprintf(hex_str + (i * 2), "%02X", data[i]);
    }

    // Null-terminate the string
    hex_str[length * 2] = '\0';

    return hex_str;
}

// Prints the shares for debugging
void print_shares(const sss_Share *shares, size_t count) {
    for (size_t i = 0; i < count; i++) {
        printf("Share %zu: ", i + 1);
        print_hex(shares[i], sss_SHARE_LEN);
    }
}

char* main(int argc, char *argv[]) {
    if (argc != THRESHOLD + 1) {
        fprintf(stderr, "Usage: %s <hex_share1> <hex_share2> <hex_share3>\n", argv[0]);
        return "";
    }

    // Allocate memory for shares
    sss_Share shares[THRESHOLD];
    uint8_t restored[sss_MLEN];

    // Parse hex strings into shares
    for (int i = 0; i < THRESHOLD; i++) {
        if (strlen(argv[i + 1]) != sss_SHARE_LEN * 2) { // Use sss_SHARE_LEN for share length
            fprintf(stderr, "Error: Share %d is not the correct length. Expected %d hex characters.\n", i + 1, sss_SHARE_LEN * 2);
            return "";
        }
        hex_to_bytes(argv[i + 1], shares[i], sss_SHARE_LEN);
    }

    // Print parsed shares for debugging
    print_shares((const sss_Share *)shares, THRESHOLD);

    // Combine the shares to restore the original secret
    int tmp = sss_combine_shares(restored, (const sss_Share *)shares, THRESHOLD);
    if (tmp != 0) {
        fprintf(stderr, "Failed to combine shares.\n");
        return "";
    }

    // Print the restored secret in hexadecimal format
    printf("Restored secret: ");
    char *hex_str = get_hex_key(restored, ETH_PRIVATE_KEY_SIZE);
    printf("%s\n", hex_str);

    return hex_str;
}
