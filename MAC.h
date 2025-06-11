// MAC.h
// Class for generating and verifying Message Authentication Codes (MAC)
// over cleartext and ciphertext data using homomorphic encryption (HE).

#pragma once

#include <iostream>
#include <vector>
#include <math.h>
#include "Constants.h"
#include "Utility.h"
#include "Secret_Sharing.h"
#include "Key_Generator.h"
#include "Destination_Server/DS_Performance_metrics.h"

using std::shared_ptr, std::make_shared;
using namespace utility;

// ------------------------------------------------------------------------
// Structs for different MAC tag representations
// ------------------------------------------------------------------------


// Struct representing a simple MAC tag for a single message.
struct single_mac_tag {
    double z_qmskd;
    double z_r;
    double y_r;
};

// Struct representing vector key components used for MAC generation.
struct key_mac {
    shared_ptr<std::vector<double>> a;
    shared_ptr<std::vector<double>> b;
    shared_ptr<std::vector<double>> c;
    shared_ptr<std::vector<double>> d;
} typedef key_mac;

// ------------------------------------------------------------------------
// HE-specific MAC tag struct
// ------------------------------------------------------------------------

// Struct representing a MAC tag over ciphertext.
struct mac_tag_ct {
    shared_ptr<Ciphertext> z_qmskd_ct;
    shared_ptr<Ciphertext> t_r_ct;
} typedef mac_tag_ct;

// ------------------------------------------------------------------------
// Cleartext MAC Structs for new optimized batched scheme
// ------------------------------------------------------------------------

// Optimized representation of a batched MAC tag.
struct mac_tag_batched_optimized {
    std::vector<double> mac_part1;
    std::vector<unsigned char> mac_part2;
};

// Struct representing a compact version of a MAC tag
// for batched operations, separating integer and fractional parts.
struct compact_mac_tag {
    shared_ptr<std::vector<double>> y_r;
    shared_ptr<std::vector<double>> y_alpha_int;
    shared_ptr<std::vector<double>> y_alpha_frac;
    shared_ptr<std::vector<double>> y_beta_int;
    shared_ptr<std::vector<double>> y_beta_frac;
} typedef compact_mac_tag;

// ------------------------------------------------------------------------
// MAC Class Declaration
// ------------------------------------------------------------------------

/**
 * @class MAC
 * Class responsible for generating and verifying MACs over both
 * cleartext and ciphertext data. Supports both batched and unbatched modes.
 */
class MAC {
private:
    // Encryption parameters used in HE operations
    enc_init_params_s _enc_init_params;

    // Buffers for intermediate results in batched MAC accumulation
    std::vector<Ciphertext> a_int_times_x_int;
    std::vector<Ciphertext> a_frac_times_x_frac;

public:
    // Constructor
    MAC(enc_init_params_s enc_init_params);

    // Destructor
    ~MAC() {}

    // Copy Constructor
    MAC(const MAC& mac) {}

    // --------------------------------------------------------------------
    // Low-level utility functions
    // --------------------------------------------------------------------

    /**
     * Multiply ciphertext by plaintext in-place, with rescaling and setting scale.
     * @param seal_struct SEAL context and keys
     * @param ct Ciphertext to multiply (in-place)
     * @param pt Plaintext multiplier
     * @return Reference to modified ciphertext
     */
    Ciphertext& mult_ct_pt_inplace(const shared_ptr<seal_struct> seal_struct, Ciphertext& ct, const Plaintext& pt);

    // --------------------------------------------------------------------
    // Batched MAC Functions
    // --------------------------------------------------------------------

    /**
     * Generate optimized batched MAC tag.
     * @param kmac Batched key generator
     * @param y_vec Vector of input values
     * @return Optimized batched MAC tag
     */
    mac_tag_batched_optimized compact_mac_batched_optimized(Batched_Key_Generator kmac, std::vector<double> y_vec);

    /**
     * Generate compact batched MAC tag.
     * @param kmac_vec Vector of batched key generators
     * @param x_int Integer part of inputs
     * @param x_frac Fractional part of inputs
     * @param input_size Number of inputs
     * @return Compact batched MAC tag
     */
    compact_mac_tag compact_mac(std::vector<Batched_Key_Generator>& kmac_vec, std::vector<std::vector<double>>& x_int, std::vector<std::vector<double>>& x_frac, ullong input_size);

    /**
     * Verify batched MAC (compute y term).
     * @param seal_struct SEAL context and keys
     * @param kmac Batched key generator
     * @param ct_x_int Ciphertext of integer part
     * @param ct_x_frac Ciphertext of fractional part
     * @param performanceMetrics Metrics for performance evaluation
     * @return Ciphertext of verification result
     */
    Ciphertext verifyHE_batched_y(const shared_ptr<seal_struct> seal_struct, Batched_Key_Generator kmac, Ciphertext ct_x_int, Ciphertext ct_x_frac, DS_performance_metrics* performanceMetrics);

    /**
     * Verify batched MAC tag (compute y_tag term).
     * @param seal_struct SEAL context and keys
     * @param len_vec Length of vector
     * @param kmac Batched key generator
     * @param ct_tr Ciphertext of tag
     * @param ct_alpha_int Ciphertext of alpha integer part
     * @param ct_beta_int Ciphertext of beta integer part
     * @param performanceMetrics Metrics for performance evaluation
     * @return Ciphertext of verification result
     */
    Ciphertext verifyHE_batched_y_tag(const shared_ptr<seal_struct> seal_struct, int len_vec, Batched_Key_Generator kmac, Ciphertext ct_tr, Ciphertext ct_alpha_int, Ciphertext ct_beta_int, DS_performance_metrics* performanceMetrics);

    // --------------------------------------------------------------------
    // Unbatched MAC Functions
    // --------------------------------------------------------------------

    /**
     * Derive compact MAC key generator for unbatched single input.
     * @param hmac HMAC object for key derivation
     * @param start_index Starting index for key derivation
     * @param amount Number of keys to derive
     * @return Derived key generator
     */
    Key_Generator Derive_compact_kmac_unbatched_single(CryptoPP::HMAC<SHA256>& hmac, ullong start_index, ullong amount);

    /**
     * Generate a compact MAC tag for a single input.
     * @param kmac Key generator
     * @param index Input index
     * @param x_int Integer part of input
     * @param x_frac Fractional part of input
     * @return Single MAC tag
     */
    single_mac_tag single_compact_mac(Key_Generator kmac, int index, double x_int, double x_frac);

    /**
     * Verify compact MAC for unbatched input (HE version).
     * @param seal_struct SEAL context and keys
     * @param kmac Key generator
     * @param x_int Ciphertext of integer part
     * @param x_frac Ciphertext of fractional part
     * @param tag_he MAC tag (HE)
     * @param squareDiff If true, compute squared difference; otherwise linear
     * @param len Input length
     * @param performanceMetrics Metrics for performance evaluation
     * @return Ciphertext of verification result
     */
    const Ciphertext& compact_unbatched_VerifyHE(const shared_ptr<seal_struct> seal_struct, Key_Generator kmac, Ciphertext& x_int,
        Ciphertext& x_frac, mac_tag_ct& tag_he, bool squareDiff, int len, DS_performance_metrics* performanceMetrics);

};
