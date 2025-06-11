#pragma once

#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <cmath>
#include "seal/seal.h"
#include <aws/core/Aws.h>
#include <aws/s3/S3Client.h>
#include "Constants.h"

// CryptoPP includes
#include "cryptopp/cryptlib.h"
#include "cryptopp/files.h"
#include "cryptopp/hex.h"
#include "cryptopp/sha.h"
#include "cryptopp/hmac.h"
#include "cryptopp/hkdf.h"

using namespace CryptoPP;
using namespace seal;
using namespace std::chrono;
using namespace Aws;
using std::endl;
using std::cout;
using std::vector;
using std::string;
using std::tuple;

// S3Utility class for AWS S3 bucket interactions
class S3Utility
{
private:
    Aws::S3::S3Client m_s3_client;

public:
    // Constructor: initialize S3 client with given region
    S3Utility(const Aws::String& region);

    // Destructor
    ~S3Utility() {};

    // Load object from S3 bucket into buffer
    const bool load_from_bucket(const Aws::String& objectKey, const Aws::String& fromBucket, int size, char* buffer);

    // Save buffer content to S3 bucket
    const bool save_to_bucket(const Aws::String& object_key, const Aws::String& to_bucket, std::string buffer);
};

namespace utility
{
    // Struct holding encryption initialization parameters
    struct enc_init_params_s
    {
        ullong prime;
        ullong prime_minus_1;
        int polyDegree;
        int max_ct_entries;
        double scale;
        std::vector<int> bit_sizes;
        int float_precision_for_test;
        int num_of_bits_prime;
        int prime_bits_to_bytes;

        // Assignment operator
        enc_init_params_s& operator=(const enc_init_params_s& a)
        {
            prime = a.prime;
            prime_minus_1 = a.prime_minus_1;
            polyDegree = a.polyDegree;
            max_ct_entries = a.max_ct_entries;
            scale = a.scale;
            bit_sizes = a.bit_sizes;
            float_precision_for_test = a.float_precision_for_test;
            num_of_bits_prime = (std::log2(a.prime));
            prime_bits_to_bytes = std::ceil(std::log2(a.prime) / 8.0);

            return *this;
        }
    };

    // Retrieve encryption parameters from S3 bucket
    bool GetEncryptionParamsFromBucket(
        const Aws::String& objectKey,
        const Aws::String& fromBucket,
        const Aws::String& region,
        EncryptionParameters& parms);

    // Retrieve public key from S3 bucket
    bool GetPublicKeyFromBucket(
        const Aws::String& objectKey,
        const Aws::String& fromBucket,
        const Aws::String& region,
        SEALContext context_ptr,
        seal::PublicKey& pk_fhe);

    // Retrieve secret key from S3 bucket
    bool GetSecretKeyFromBucket(
        const Aws::String& objectKey,
        const Aws::String& fromBucket,
        const Aws::String& region,
        SEALContext context_ptr,
        SecretKey& sk_fhe);

    // Generate a random double x in range [min, max)
    double x_gen(double min, double max);

    // Generate vector of random integers in range [min, max), size amount
    vector<double> x_gen_int(int min, ullong max, ullong amount);

    // Timer utility functions

    // Open file for recording timing metrics
    std::ofstream openMetricsFile(int input_size, string metrics_file_name);

    // Start timer and return start time point
    high_resolution_clock::time_point timer_start();

    // Calculate elapsed nanoseconds from start time point
    nanoseconds timer_end(high_resolution_clock::time_point start);

    // Serialize a SEAL ciphertext to string
    std::string serialize_fhe(Ciphertext ct_input);

    // Deserialize a SEAL ciphertext from string
    void deserialize_fhe(std::string str, Ciphertext& ct_output, SEALContext& context);

    // Deserialize a SEAL ciphertext from raw char buffer
    void deserialize_fhe(const char* str, std::size_t size, Ciphertext& ct_output, SEALContext& context);

    // Initialize encryption parameters from a file
    void InitEncParams(enc_init_params_s* enc_init_params, string fileName);
}
