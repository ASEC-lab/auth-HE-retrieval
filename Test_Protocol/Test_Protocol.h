#pragma once

#include "seal/seal.h"
#include "../Secret_Sharing.h"
#include "../Servers_Protocol.h"
#include "../Utility.h"
#include "../Constants.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <vector>

#define MAX_FILE_NAME 256

using std::cout;  using std::endl;
using std::string;  using std::vector;
using std::shared_ptr;

// Global counter (used across multiple files)
inline int counter = 0;

// Timer / performance metrics class for protocol
class TP_performance_metrics
{
public:
    // Timers for each phase (with MAC)
    long long encode = 0;
    long long encrypt = 0;
    long long serialize = 0;
    long long store = 0;
    long long load = 0;
    long long deserialize = 0;
    long long hmac = 0;
    long long verify = 0;

    // Timers for each phase (without MAC)
    long long encode_no_mac = 0;
    long long encrypt_no_mac = 0;
    long long serialize_no_mac = 0;
    long long store_no_mac = 0;
    long long load_no_mac = 0;
    long long deserialize_no_mac = 0;
    long long decode_no_mac = 0;
    long long decrypt_no_mac = 0;

    long long hkdf = 0; // Key derivation timer

    // Returns header string for performance report
    static std::string getHeader();
};

// Overload << to print performance metrics
std::ostream& operator<<(std::ostream&, const TP_performance_metrics& tpPerformanceMetrics);

// Protocol test class — tests correctness and functionality of protocol
class Test_Protocol
{
private:
    vector<double> _secret_num_vec;        // Original secret vector
    enc_init_params_s _enc_init_params;    // Encryption params (polyDegree, coeff modulus, scale, etc.)

public:
    // Constructor / destructor / copy constructor
    Test_Protocol(string enc_params_file); // Initialize using enc params file
    ~Test_Protocol() {}
    Test_Protocol(const Test_Protocol& test_protocol) {} // Copy constructor

    // Generate SEAL struct from loaded parameters
    shared_ptr<seal_struct> set_seal_struct();

    // Test HKDF correctness and performance
    void test_hkdf(TP_performance_metrics& performanceMetrics);

    // Test CryptoSink + HMAC output correctness and performance
    void test_crypto_sink_hmac(TP_performance_metrics& performanceMetrics);

    // Simulated storage test — batched
    void test_storage_batched_sim();

    // Unbatched storage test — with or without MAC
    void test_storage_unbatched(ullong input_size, shared_ptr<seal_struct> seal, bool with_mac, TP_performance_metrics& performanceMetrics);

    // HMAC on FHE ciphertexts — batched
    void hmac_on_FHE(ullong input_size, shared_ptr<seal_struct> seal, TP_performance_metrics& performanceMetrics);

    // Test compact batched MAC verification (optimized version)
    int test_compact_HE_mac_optimized(ullong input_size);

    // Local copy of batched MAC verification (ciphertext version) — used for testing only
    Ciphertext verifyHE_batched_y(const shared_ptr<seal_struct> seal_struct, Batched_Key_Generator kmac, Ciphertext ct_x_int, Ciphertext ct_x_frac);

    // Local copy of batched MAC verification with tag — used for testing only
    Ciphertext verifyHE_batched_y_tag(const shared_ptr<seal_struct> seal_struct, int len_vec, Batched_Key_Generator kmac, Ciphertext ct_tr, Ciphertext ct_alpha_int, Ciphertext ct_beta_int);
};

// Namespace for testing correctness of protocol (unit tests)
namespace test_correctness
{
    // Check whether secret sharing result matches original vector (batched test)
    int is_correct_secret_sharing(shared_ptr<vector<Ciphertext>> x_final_CT,
                                  shared_ptr<seal_struct> seal,
                                  const vector<double>& x_origin,
                                  int input_size,
                                  int max_ct_entries);

    // Check whether encrypted MAC output is valid (HE version)
    bool is_MAC_HE_valid(shared_ptr<seal_struct> seal_struct,
                         shared_ptr<vector<Ciphertext>> diffCt,
                         int input_size,
                         int max_ct_entries,
                         string mac_type,
                         bool compactMac);

    // Check whether plaintext MAC output is valid
    bool is_MAC_PT_valid(vector<double> diff_vec,
                         int input_size,
                         int max_ct_entries,
                         string mac_type);
};
