#include "Secret_Sharing.h"

using namespace utility;

// Constructor
Secret_Sharing::Secret_Sharing(enc_init_params_s enc_init_params)
{
    _enc_init_params = enc_init_params;
}

// Recombine shares into one FHE ciphertext
const Ciphertext& Secret_Sharing::Rec_CT(
    const vector<double>& cleartext_vec,
    const vector<double>& cleartext_for_cipher_vec,
    Ciphertext& x_int_FHE,
    Ciphertext& x_frac_FHE,
    const shared_ptr<seal_struct> context)
{
    Plaintext encoded_cleartext_vec, encoded_cleartext_for_cipher_vec;

    context->encoder_ptr->encode(cleartext_vec, _enc_init_params.scale, encoded_cleartext_vec);
    context->encoder_ptr->encode(cleartext_for_cipher_vec, _enc_init_params.scale, encoded_cleartext_for_cipher_vec);

    context->evaluator_ptr->add_plain_inplace(x_frac_FHE, encoded_cleartext_vec);
    context->evaluator_ptr->multiply_plain_inplace(x_int_FHE, encoded_cleartext_for_cipher_vec);

    context->evaluator_ptr->rescale_to_next_inplace(x_int_FHE);
    context->evaluator_ptr->mod_switch_to_next_inplace(x_frac_FHE);

    x_int_FHE.scale() = _enc_init_params.scale;

    context->evaluator_ptr->add_inplace(x_frac_FHE, x_int_FHE);

    return x_frac_FHE;
}

// Helper: generate initial b and t from derived key bytes
void gen_b_t_init_values(ullong *b_init, ullong *t_init, int prime_bit_num, unsigned char *derived_key)
{
    int shift = 0;
    int mask;
    int mask_pow;
    int prime_byte_num = ceil(prime_bit_num / 8.0);

    // Process full bytes
    for(int i = 0; i < prime_byte_num - 1; i++)
    {
        *b_init |= ((ullong)derived_key[i] << shift);
        *t_init |= ((ullong)derived_key[prime_byte_num + i] << shift);
        shift += 8;
    }

    // Handle last byte (partial bits if needed)
    mask_pow = ((prime_bit_num % 8) == 0) ? 8 : (prime_bit_num % 8);
    mask = (1 << mask_pow) - 1;

    *b_init |= (((ullong)derived_key[prime_byte_num - 1] & mask) << shift);
    *t_init |= (((ullong)derived_key[2 * prime_byte_num - 1] & mask) << shift);
}

// Derive b and t using SHARE_MAC_KEYS (HKDF version)
sharePT_struct Secret_Sharing::Derive_b_t(SHARE_MAC_KEYS *keys, int prime_bits_to_bytes)
{
    ullong t1 = 0;
    int b1 = 0;

    // Derive t from bytes
    for(int i = 0; i < prime_bits_to_bytes; i++)
    {
        t1 |= ((ullong)keys->get_next_byte() << (8 * i));
    }

    // Derive b as one bit
    b1 = keys->get_next_byte() & 0x1;

    // Populate struct
    sharePT_struct shared_struct;
    shared_struct.x_int = 0.0;  // placeholder
    shared_struct.x_frac = 0.0; // placeholder
    shared_struct.t = t1 % _enc_init_params.prime;
    shared_struct.b = b1;

    return shared_struct;
}

// Derive b and t using Crypto++ HMAC
sharePT_struct Secret_Sharing::Derive_b_t(CryptoPP::HMAC<CryptoPP::SHA256> hmac, int index)
{
    std::string derivation_data("storage_test_" + std::to_string(index));

    int prime_bit_num = ceil(log2(_enc_init_params.prime));
    ullong b_init = 0;
    ullong t_init = 0;

    // Generate derived key
    Key_Generator k_mac(_enc_init_params.prime);
    std::string derived_key = k_mac.derive_rand_key(hmac, derivation_data);

    // Generate b_init and t_init
    gen_b_t_init_values(&b_init, &t_init, prime_bit_num, (unsigned char*)derived_key.c_str());

    // Extract b and t from b_init and t_init
    int b = b_init / _enc_init_params.prime;
    llong t = t_init % _enc_init_params.prime;

    // Populate struct
    sharePT_struct shared_struct;
    shared_struct.x_int = 0.0;  // placeholder
    shared_struct.x_frac = 0.0; // placeholder
    shared_struct.t = t;
    shared_struct.b = b;

    return shared_struct;
}

// Generate one share given input x and secret_share_keys
sharePT_struct Secret_Sharing::gen_share(ullong x, SHARE_MAC_KEYS *secret_share_keys, int prime_bits_to_bytes)
{
    sharePT_struct shared_struct = Derive_b_t(secret_share_keys, prime_bits_to_bytes);

    int x_int = ((x + shared_struct.t) / _enc_init_params.prime + shared_struct.b) % 2;
    ullong x_frac = ((x + shared_struct.t) % _enc_init_params.prime);

    shared_struct.x_int = (double)x_int;
    shared_struct.x_frac = (double)x_frac;

    return shared_struct;
}

// Main share function - generate shares for vector of inputs using HMAC
nanoseconds Secret_Sharing::Share(
    vector<double> secret_num_vec,
    CryptoPP::HMAC<CryptoPP::SHA256> hmac,
    ullong num_of_secrets,
    std::ostringstream *os)
{
    ullong x;
    nanoseconds share_time{0};

    for (ullong i = 0; i < num_of_secrets; i++)
    {
        x = secret_num_vec[i];

        // Time start
        auto start_share = utility::timer_start();

        // Derive share
        sharePT_struct shared_struct = Derive_b_t(hmac, i);

        int x_int = ((x + shared_struct.t) / _enc_init_params.prime + shared_struct.b) % 2;
        ullong x_frac = ((x + shared_struct.t) % _enc_init_params.prime);

        shared_struct.x_int = (double)x_int;
        shared_struct.x_frac = (double)x_frac;

        // Time end
        share_time += utility::timer_end(start_share);

        // Write share to output stream
        os->write(reinterpret_cast<const char*>(&shared_struct.x_int), sizeof(double));
        os->write(reinterpret_cast<const char*>(&shared_struct.x_frac), sizeof(double));
    }

    return share_time;
}
