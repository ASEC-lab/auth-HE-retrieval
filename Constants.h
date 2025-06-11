#ifndef CONSTANTS_H
#define CONSTANTS_H

// Type aliases
typedef unsigned long long ullong;
typedef long long llong;
typedef unsigned char byte;

// Protocol constants
const int BLOCK_SIZE_BYTES { 16 };            // AES block size in bytes
const int KEY_SIZE_BYTES { 32 };              // AES key size in bytes (256 bits)
const int MAX_SOCKET_SEND_RETRIES { 15 };     // Max retries for socket send

// Constants namespace
namespace constants
{
    // Prime used for modular arithmetic in the protocol
    constexpr ullong prime = 222863;
    constexpr ullong prime_minus_1 = prime - 1;

    // SEAL parameters
    inline int polyDegree { 16384 };                     // Polynomial modulus degree
    inline std::vector<int> bit_sizes({60,60,60,60,60}); // Coefficient modulus bit sizes
    const inline double SCALE { pow(2.0, 60) };          // Scale parameter for CKKS encoding

    inline int DEFAULT_INPUT_SIZE = 16;    // Default number of inputs; 1 = unbatched
    inline int NUM_DATAPOINTS_IN_BLOCK = 16000000; // Max number of datapoints in a block
    inline int MAX_CT_ENTRIES = polyDegree / 2;    // Max number of slots available in ciphertext

    // Debug / validation constants
    const int max_reported_incorrect_items = 10; // Max number of incorrect MAC/secret share items to report

    // File names for keys
    inline std::string SECRET_SHARE_KEY_FILENAME("key_DS.txt"); // Secret share key file
    inline std::string TAG_SQ_KEY_FILENAME("key_sq.txt");       // MAC tag Sq key file
    inline std::string TAG_SR_KEY_FILENAME("key_sr.txt");       // MAC tag Sr key file

    // Info strings used for key derivation (HKDF/HMAC info field)
    const std::string MAC_DERIVE_KEY = "storage_test_MAC_";   // MAC key derivation info
    const std::string SECRET_SHARE_DERIVE_KEY = "storage_test_"; // Secret share key derivation info
}

#endif
