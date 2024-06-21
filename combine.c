#include "sss.h" // Include Shamir's Secret Sharing header
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define THRESHOLD 3 // Recombination threshold

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

// Prints the shares for debugging
void print_shares(const sss_Share *shares, size_t count) {
    for (size_t i = 0; i < count; i++) {
        printf("Share %zu: ", i + 1);
        print_hex(shares[i], sss_SHARE_LEN);
    }
}

int main(int argc, char *argv[]) {
    if (argc != THRESHOLD + 1) {
        fprintf(stderr, "Usage: %s <hex_share1> <hex_share2> <hex_share3>\n", argv[0]);
        return 1;
    }

    // Allocate memory for shares
    sss_Share shares[THRESHOLD];
    uint8_t restored[sss_MLEN];

    // Parse hex strings into shares
    for (int i = 0; i < THRESHOLD; i++) {
        if (strlen(argv[i + 1]) != sss_SHARE_LEN * 2) { // Use sss_SHARE_LEN for share length
            fprintf(stderr, "Error: Share %d is not the correct length. Expected %d hex characters.\n", i + 1, sss_SHARE_LEN * 2);
            return 1;
        }
        hex_to_bytes(argv[i + 1], shares[i], sss_SHARE_LEN);
    }

    // Print parsed shares for debugging
    print_shares((const sss_Share *)shares, THRESHOLD);

    // Combine the shares to restore the original secret
    int tmp = sss_combine_shares(restored, (const sss_Share *)shares, THRESHOLD);
    if (tmp != 0) {
        fprintf(stderr, "Failed to combine shares.\n");
        return 1;
    }

    // Print the restored secret in hexadecimal format
    printf("Restored secret: ");
    print_hex(restored, sss_MLEN);

    // Print the restored secret as a string for verification
    printf("Restored secret as string: %s\n", restored);

    return 0;
}
