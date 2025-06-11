#pragma once

//includes for SEAL library
#include "seal/seal.h"
#include "seal/evaluator.h" // for basic operation on FHE data
#include "seal/util/polyarithsmallmod.h"

//std includes
#include <iomanip>
#include <fstream>
#include <iostream>
#include <string>
#include <math.h>
#include <chrono>

//project includes
#include "Constants.h"
#include "Utility.h"
#include "Key_Generator.h"

//includes for CryptoPP
#include "cryptopp/cryptlib.h"
#include "cryptopp/files.h"
#include "cryptopp/hex.h"
#include "cryptopp/sha.h"
#include "cryptopp/hmac.h"

using namespace CryptoPP;
using namespace seal;
using namespace utility;

using std::tuple, std::make_tuple;
using std::vector;
using std::cout, std::endl, std::pow;
using std::chrono::nanoseconds;
using std::unique_ptr, std::make_unique;
using std::shared_ptr, std::make_shared;


//STRUCTS

// Struct for share algorithm output (for plaintext value)
struct sharePT {
	ullong t;
	int  b;
	double x_int;
	double x_frac;
	double x_int_plus_x_frac;
} typedef sharePT_struct;

// Struct for SEAL initialization and context (used in protocol setup)
struct seal_struct {
	SEALContext context_ptr;                // SEAL context object
	shared_ptr<Evaluator> evaluator_ptr;    // Evaluator for HE operations
	shared_ptr<CKKSEncoder> encoder_ptr;    // Encoder for CKKS scheme
	shared_ptr<KeyGenerator> keygen_ptr;    // Key generator
	shared_ptr<Encryptor> encryptor_ptr;    // Encryptor
	shared_ptr<Decryptor> decryptor_ptr;    // Decryptor
	shared_ptr<seal::PublicKey> pk_ptr;     // Public key
	shared_ptr<SecretKey> sk_ptr;           // Secret key

    shared_ptr<RelinKeys> relink_ptr;       // Relinearization keys
	int poly_modulus_degree;                // Polynomial modulus degree
	vector<int> bit_sizes;                  // Modulus sizes
	double scale;                           // CKKS scale
} typedef seal_struct;


/**
 * @class Secret_Shraing
 * Class for secret sharing operations, share on PT and Reconstruct on ciphertext.
 */

class Secret_Sharing {
private:
    enc_init_params_s _enc_init_params;
    std::vector<byte> _keys;

public:
    // Constructor
	Secret_Sharing(enc_init_params_s _enc_inite_params);

    // Secret sharing using HKDF keys
    sharePT_struct Derive_b_t(SHARE_MAC_KEYS *keys, int prime_bits_to_bytes);

    // Secret sharing using HMAC-based derivation
    sharePT_struct Derive_b_t(CryptoPP::HMAC<CryptoPP::SHA256> hmac, int index);

    // Main share function (for a vector of secrets), outputs serialized shares
    nanoseconds Share(vector<double> secret_num_vec, CryptoPP::HMAC<CryptoPP::SHA256> hmac, ullong num_of_secrets, std::ostringstream *os);

    // Generate one share from x and secret_share_keys
    sharePT_struct gen_share(ullong x, SHARE_MAC_KEYS *secret_share_keys, int prime_bits_to_bytes);

    // Recombine shares into FHE ciphertexts
    const Ciphertext& Rec_CT(const vector<double>& cleartext_vec, const vector<double>& cleartext_for_cipher_vec, Ciphertext& x_int_FHE, Ciphertext& x_frac_FHE, const shared_ptr<seal_struct> context);

};
