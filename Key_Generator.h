#ifndef Key_Generator_H
#define Key_Generator_H

#include "Utility.h"


/**
 * @class Key_Generator
 * Base class for generating secret sharing keys (a, b, c_alpha, d_alpha) from HMAC or HKDF.
 */
class Key_Generator {
public:
    // Public key vectors
    vector<double> a_int;
    vector<double> a_frac;
    vector<double> b;
    vector<double> c_alpha;
    vector<double> d_alpha;

    // Constructor / Destructor
    Key_Generator(ullong prime = constants::prime);
    virtual ~Key_Generator();

    // Derive vectors a, b, c_alpha, d_alpha using HMAC and derived key
    virtual void derive_abcd(CryptoPP::HMAC<SHA256>& hmac, std::string derived_key, ullong start_index, ullong amount);

    // Derive random key (HMAC version)
    std::string derive_rand_key(CryptoPP::HMAC<SHA256> hmac, std::string derivation_data);

    // Derive random key using HKDF
    void derive_rand_key_hkdf(byte* key_tag, int key_tag_len, std::string cur_derivation_data, std::vector<byte>& keys, int key_len);

protected:
    ullong _prime;
};


/**
 * @class SHARE_MAC_KEYS
 * Helper class for MAC key management (used in share generation).
 */
class SHARE_MAC_KEYS {
public:
    // Constructor / Destructor
    SHARE_MAC_KEYS() {};
    SHARE_MAC_KEYS(int key_length);
    virtual ~SHARE_MAC_KEYS();

    // Key material and iteration state
    int key_len;
    vector<byte> keys;
    int keys_iter;

    // Generate keys using HKDF
    void gen_keys(byte* key_tag, int key_tag_len, std::string info);

    // Return next byte from keys vector
    byte get_next_byte(void);
};


/**
 * @class Batched_Key_Generator
 * Derived class from Key_Generator for generating batch keys (adds c_beta and d_beta).
 */
class Batched_Key_Generator : public Key_Generator {
public:
    vector<double> c_beta;
    vector<double> d_beta;

    // Constructor
    Batched_Key_Generator(ullong prime);

    // Derive vector a for batching
    void derive_a(SHARE_MAC_KEYS *kmac_keys, ullong start_index, ullong ct_max_index, int bytes_per_a);

    // Derive vectors b, c_beta, d_beta for batching
    void derive_bcd(SHARE_MAC_KEYS *kmac_keys, int amount, int bytes_per_cd, int start_iter_index);
};


#endif // Key_Generator_H
