#pragma once

// Standard libraries
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>

// Project includes
#include "Utility.h"
#include "Secret_Sharing.h"
#include "MAC.h"

using namespace utility;

// Directory paths used for storing ciphertexts and tags
inline const char* CIPHERTEXTS_BT_T_DIR {"ciphertexts_b_t"};          // Directory for ciphertexts b_t
inline const char* CIPHERTEXTS_X_INT_FRAC_DIR {"ciphertexts_x_int_frac"}; // Directory for ciphertexts x integer and fractional parts

inline const char* TAGS_SQ_DIR {"tags_sq"};      // Directory for storing tag files (square terms)
inline const char* TAGS_SR_DIR {"tags_sr"};      // Directory for storing tag files (random terms)

// Flag to enable/disable batching for AES operations
inline bool use_batch_for_aes {true};

// AWS S3 parameters namespace
namespace awsparams {
    // AWS S3 bucket configuration
    inline const char* bucket_name = "secret-share-bucket";   // Target S3 bucket name
    inline const char* region = "eu-central-1";               // Target AWS region
}

// Convenience aliases
using std::shared_ptr;
using std::make_shared;
using std::string;

// Servers_Protocol class - encapsulates protocol server functions
class Servers_Protocol
{
public:
    // Default constructor
    Servers_Protocol() {}

    // Distributed Square (DS) function
    // Performs distributed computation over encrypted x_int and x_frac vectors
    // Returns a vector of Ciphertexts representing the result
    shared_ptr<vector<Ciphertext>> DS(
        const shared_ptr<vector<Ciphertext>> x_int_FHE,
        const shared_ptr<vector<Ciphertext>> x_frac_FHE,
        shared_ptr<seal_struct> seal
    );

    // Generate SEAL encryption parameters (version with bit_sizes)
    // Creates encryption context, keygen, evaluator, encoder, and public key
    shared_ptr<seal_struct> gen_seal_params(
        int poly_modulus_degree,               // Polynomial modulus degree (degree of poly ring)
        vector<int> bit_sizes,                 // Bit sizes for coefficient moduli
        double scale                           // Scaling factor for CKKS encoding
    );

    // Generate SEAL encryption parameters (version with explicit coeff_modulus vector)
    // Creates encryption context, keygen, evaluator, encoder, and public key
    shared_ptr<seal_struct> gen_seal_params(
        int poly_modulus_degree,               // Polynomial modulus degree (degree of poly ring)
        vector<seal::Modulus> coeff_modulus,   // Precomputed coefficient modulus vector
        double scale                           // Scaling factor for CKKS encoding
    );
};
