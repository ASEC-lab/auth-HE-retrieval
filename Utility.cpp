#include "Utility.h"
#include <sstream>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/PutObjectRequest.h>

using namespace Aws;

// Constructor for S3Utility. Initializes the S3 client with given AWS region.
S3Utility::S3Utility(const Aws::String& region) {
    Aws::Client::ClientConfiguration config;
    config.region = region;
    Aws::S3::S3Client s3_client(config);
    m_s3_client = s3_client;
}

// Loads an object from an S3 bucket into a buffer.
const bool S3Utility::load_from_bucket(const Aws::String& objectKey, const Aws::String& fromBucket, int size, char* buffer) {

    Aws::S3::Model::GetObjectRequest object_request;
    object_request.SetBucket(fromBucket);
    object_request.SetKey(objectKey);

    Aws::S3::Model::GetObjectOutcome get_object_outcome = m_s3_client.GetObject(object_request);

    if (get_object_outcome.IsSuccess()) {
        Aws::IOStream& out = get_object_outcome.GetResultWithOwnership().GetBody();
        out.read(buffer, size);
        return true;
    } else {
        auto err = get_object_outcome.GetError();
        std::cout << "Error: GetObject: " << err.GetExceptionName() << ": " << err.GetMessage() << std::endl;
        return false;
    }
}

// Saves a buffer as an object to an S3 bucket.
const bool S3Utility::save_to_bucket(const Aws::String& object_key, const Aws::String& to_bucket, std::string buffer) {

    Aws::S3::Model::PutObjectRequest request;
    request.SetBucket(to_bucket);
    request.SetKey(object_key);

    std::shared_ptr<Aws::IOStream> input_data = Aws::MakeShared<Aws::StringStream>("SampleAllocationTag", buffer, std::ios_base::in | std::ios_base::binary);
    request.SetBody(input_data);

    Aws::S3::Model::PutObjectOutcome outcome = m_s3_client.PutObject(request);

    if (outcome.IsSuccess()) {
        std::cout << "Added object '" << object_key << "' to bucket '" << to_bucket << "'." << std::endl;
    } else {
        std::cout << "Error: PutObject: " << outcome.GetError().GetMessage() << std::endl;
        return false;
    }

    return true;
}

// Loads encryption parameters from an S3 bucket.
bool utility::GetEncryptionParamsFromBucket(const Aws::String& objectKey, const Aws::String& fromBucket, const Aws::String& region, EncryptionParameters& parms) {

    Aws::Client::ClientConfiguration config;
    if (!region.empty()) {
        config.region = region;
    }

    Aws::S3::S3Client s3_client(config);
    Aws::S3::Model::GetObjectRequest object_request;
    object_request.SetBucket(fromBucket);
    object_request.SetKey(objectKey);

    Aws::S3::Model::GetObjectOutcome get_object_outcome = s3_client.GetObject(object_request);

    if (get_object_outcome.IsSuccess()) {
        Aws::IOStream& out = get_object_outcome.GetResultWithOwnership().GetBody();
        std::cout << "Got params from S3" << std::endl;
        parms.load(out);
        std::cout << "Loaded params " << std::endl;
        return true;
    } else {
        auto err = get_object_outcome.GetError();
        std::cout << "Error: GetObject: " << err.GetExceptionName() << ": " << err.GetMessage() << std::endl;
        return false;
    }
}

// Loads public key from an S3 bucket into SEAL PublicKey object.
bool utility::GetPublicKeyFromBucket(const Aws::String& objectKey, const Aws::String& fromBucket, const Aws::String& region, SEALContext context_ptr, seal::PublicKey& pk_fhe) {

    Aws::Client::ClientConfiguration config;
    if (!region.empty()) {
        config.region = region;
    }

    Aws::S3::S3Client s3_client(config);
    Aws::S3::Model::GetObjectRequest object_request;
    object_request.SetBucket(fromBucket);
    object_request.SetKey(objectKey);

    Aws::S3::Model::GetObjectOutcome get_object_outcome = s3_client.GetObject(object_request);

    if (get_object_outcome.IsSuccess()) {
        Aws::IOStream& out = get_object_outcome.GetResultWithOwnership().GetBody();
        std::cout << "Got Key from S3" << std::endl;
        pk_fhe.load(context_ptr, out);
        std::cout << "Loaded key " << std::endl;
        return true;
    } else {
        auto err = get_object_outcome.GetError();
        std::cout << "Error: GetObject public key: " << err.GetExceptionName() << ": " << err.GetMessage() << std::endl;
        return false;
    }
}

// Loads secret key from an S3 bucket into SEAL SecretKey object.
bool utility::GetSecretKeyFromBucket(const Aws::String& objectKey, const Aws::String& fromBucket, const Aws::String& region, SEALContext context_ptr, SecretKey& sk_fhe) {

    Aws::Client::ClientConfiguration config;
    if (!region.empty()) {
        config.region = region;
    }

    Aws::S3::S3Client s3_client(config);
    Aws::S3::Model::GetObjectRequest object_request;
    object_request.SetBucket(fromBucket);
    object_request.SetKey(objectKey);

    Aws::S3::Model::GetObjectOutcome get_object_outcome = s3_client.GetObject(object_request);

    if (get_object_outcome.IsSuccess()) {
        Aws::IOStream& out = get_object_outcome.GetResultWithOwnership().GetBody();
        std::cout << "Got Key from S3" << std::endl;
        sk_fhe.load(context_ptr, out);
        std::cout << "Loaded key " << std::endl;
        return true;
    } else {
        auto err = get_object_outcome.GetError();
        std::cout << "Error: GetObject secret key: " << err.GetExceptionName() << ": " << err.GetMessage() << std::endl;
        return false;
    }
}

// Serializes SEAL Ciphertext into string.
std::string utility::serialize_fhe(Ciphertext ct_input) {
    std::ostringstream os(std::ios::binary);
    ct_input.save(os);
    return os.str();
}

// Deserializes SEAL Ciphertext from string.
void utility::deserialize_fhe(std::string str, Ciphertext& ct_output, SEALContext& context) {
    std::istringstream is(str, std::ios::in | std::ios::binary);
    std::streamoff loaded = ct_output.load(context, is);
}

// Deserializes SEAL Ciphertext from char array.
void utility::deserialize_fhe(const char* str, std::size_t size, Ciphertext& ct_output, SEALContext& context) {
    std::streamoff loaded = ct_output.load(context, (const seal_byte*)str, size);
}

// Generates a vector of random integers between min and max.
vector<double> utility::x_gen_int(int min, ullong max, ullong amount) {
    vector<double> random_num_vec;
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine gen(seed);
    std::uniform_int_distribution<ullong> real_dist(min, max);

    for (ullong i = 0; i < amount; i++) {
        random_num_vec.push_back(real_dist(gen));
    }

    return random_num_vec;
}

// Generates a random double between min and max.
double utility::x_gen(double min, double max) {
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine gen(seed);
    std::uniform_real_distribution<double> real_dist(0.0, 1.0);
    double x = real_dist(gen);
    return x;
}

// Starts a high-resolution timer.
high_resolution_clock::time_point utility::timer_start() {
    return high_resolution_clock::now();
}

// Ends a high-resolution timer and returns the elapsed time.
nanoseconds utility::timer_end(high_resolution_clock::time_point start) {
    auto stop0 = high_resolution_clock::now();
    auto duration0 = duration_cast<nanoseconds>(stop0 - start);
    return duration0;
}

// Creates folder for metrics file if not exists and opens the metrics file.
std::ofstream utility::openMetricsFile(int input_size, string metrics_file_name) {
    struct stat sb;
    std::string metrics_folder_name("/tmp/out");

    if (stat(metrics_folder_name.c_str(), &sb)) {
        std::cout << "Creating folder " << metrics_folder_name << " for metrics" << std::endl;
        const int dir_err = mkdir(metrics_folder_name.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        if (-1 == dir_err) {
            std::cout << "Error creating folder " << metrics_folder_name << std::endl;
            exit(1);
        }
    }

    metrics_file_name += std::to_string(input_size) + ".csv";
    string metrics_file_full_path = metrics_folder_name + "/" + metrics_file_name;

    std::ofstream metrics_file(metrics_file_full_path);
    if (metrics_file.is_open() == 0) {
        std::cout << "Unable to open file " << metrics_file_full_path << std::endl;
        exit(1);
    }

    return metrics_file;
}

// Loads encryption initialization parameters from file or defaults.
void utility::InitEncParams(enc_init_params_s* enc_init_params, string fileName) {

    if (fileName.empty()) {
        enc_init_params->prime = constants::prime;
        enc_init_params->prime_minus_1 = constants::prime_minus_1;
        enc_init_params->max_ct_entries = constants::MAX_CT_ENTRIES;
        enc_init_params->polyDegree = constants::polyDegree;
        enc_init_params->bit_sizes = constants::bit_sizes;
        enc_init_params->scale = constants::SCALE;
        enc_init_params->float_precision_for_test = std::to_string(constants::prime).length();
    } else {
        std::ifstream inputFile(fileName);
        if (!inputFile) {
            throw std::runtime_error("Error: Unable to open file " + fileName);
        }

        string line;
        int line_num = 0;
        while (getline(inputFile, line)) {
            if (line.empty() || line.at(0) == '#')
                continue;

            std::istringstream iss(line);
            ullong value;

            if (!(iss >> value)) {
                throw std::runtime_error("Error: Failed to read value from line " + std::to_string(line_num));
            }

            switch (line_num) {
                case 0:
                    enc_init_params->prime = value;
                    break;
                case 1:
                    enc_init_params->polyDegree = (int)value;
                    break;
                case 2:
                    enc_init_params->scale = pow(2.0, (int)value);
                    break;
                case 3:
                    enc_init_params->bit_sizes.push_back((int)value);
                    while (iss >> value) {
                        enc_init_params->bit_sizes.push_back((int)value);
                    }
                    break;
                default:
                    throw std::runtime_error("Error: Too many lines in the file");
            }

            line_num++;
        }

        if (line_num < 4) {
            throw std::runtime_error("Error: Insufficient lines in the file.");
        }

        inputFile.close();

        enc_init_params->max_ct_entries = enc_init_params->polyDegree / 2;
        enc_init_params->prime_minus_1 = enc_init_params->prime - 1;
        enc_init_params->float_precision_for_test = std::to_string(enc_init_params->prime).length();

        std::cout << "Read the following parameters from " << fileName << ":" << std::endl;
        std::cout << "prime: " << enc_init_params->prime << " scale: 2^" << log2(enc_init_params->scale) << " max_ct: " << enc_init_params->max_ct_entries << " polyDegree: " << enc_init_params->polyDegree << " prime_minus_1: " << enc_init_params->prime_minus_1 << " bit sizes:";
        for (int i = 0; i < enc_init_params->bit_sizes.size(); i++) {
            std::cout << " " << enc_init_params->bit_sizes[i];
        }
        std::cout << std::endl;
    }
}
