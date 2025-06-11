#include "Servers_Protocol.h"

// Generate SEAL encryption parameters (version with bit_sizes)
// Convenience wrapper that calls the main version of gen_seal_params() with explicit coeff_modulus
shared_ptr<seal_struct> Servers_Protocol::gen_seal_params(
    int poly_modulus_degree,
    vector<int> bit_sizes,
    double scale
)
{
    // Create coefficient modulus from bit sizes and call main gen_seal_params
    return gen_seal_params(poly_modulus_degree, CoeffModulus::Create(poly_modulus_degree, bit_sizes), scale);
}

// Generate SEAL encryption parameters (version with explicit coeff_modulus)
// Initializes SEALContext, KeyGenerator, Evaluator, Encoder, Encryptor, Decryptor, PublicKey, SecretKey, RelinKeys
shared_ptr<seal_struct> Servers_Protocol::gen_seal_params(
    int poly_modulus_degree,
    vector<seal::Modulus> coeff_modulus,
    double scale
)
{
    // Set up SEAL encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(coeff_modulus);

    // Initialize seal_struct to hold SEAL objects and parameters
    seal_struct seal { SEALContext(parms) };
    seal.context_ptr = SEALContext(parms);

    seal.poly_modulus_degree = poly_modulus_degree;
    seal.scale = scale;

    // Create core SEAL components
    seal.evaluator_ptr = make_shared<Evaluator>(seal.context_ptr);
    seal.encoder_ptr = make_shared<CKKSEncoder>(seal.context_ptr);
    seal.keygen_ptr = make_shared<KeyGenerator>(seal.context_ptr);

    // Generate PublicKey and SecretKey
    seal::PublicKey pk;
    seal.keygen_ptr->create_public_key(pk);
    SecretKey sk = seal.keygen_ptr->secret_key();

    // Initialize Encryptor, Decryptor, and store keys
    seal.encryptor_ptr = make_shared<Encryptor>(seal.context_ptr, pk);
    seal.decryptor_ptr = make_shared<Decryptor>(seal.context_ptr, sk);
    seal.pk_ptr = make_shared<seal::PublicKey>(pk);
    seal.sk_ptr = make_shared<SecretKey>(sk);

    // Generate and store RelinKeys for relinearization
    RelinKeys relin_keys;
    seal.keygen_ptr->create_relin_keys(relin_keys);
    seal.relink_ptr = make_shared<RelinKeys>(relin_keys);

    // Return fully initialized seal_struct
    return make_shared<seal_struct>(seal);
}
