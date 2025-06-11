#include "Test_Protocol.h"
#include "../Utility.h"
#include <aws/core/Aws.h>
#include <aws/core/utils/logging/LogLevel.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <iomanip>
#include <cryptopp/osrng.h>

using namespace Aws;


std::ostream& operator<<(std::ostream& out, const TP_performance_metrics& tpPerformanceMetrics) {
    return out << tpPerformanceMetrics.encode/1000 <<","<< tpPerformanceMetrics.encrypt/1000 <<","<< tpPerformanceMetrics.serialize/1000<<
    ","<< tpPerformanceMetrics.store/1000 <<","<< tpPerformanceMetrics.load/1000 << ","<< tpPerformanceMetrics.deserialize/1000 <<
    "," <<tpPerformanceMetrics.hmac/1000 <<"," <<tpPerformanceMetrics.verify/1000 <<
    ","<<tpPerformanceMetrics.encode_no_mac/1000 <<","<< tpPerformanceMetrics.encrypt_no_mac/1000 <<","<< tpPerformanceMetrics.serialize_no_mac/1000<<
    ","<< tpPerformanceMetrics.store_no_mac/1000 <<","<< tpPerformanceMetrics.load_no_mac/1000<< ","<< tpPerformanceMetrics.deserialize_no_mac/1000<<
    ","<< tpPerformanceMetrics.hkdf/1000<< ","<< tpPerformanceMetrics.decode_no_mac/1000<<","<< tpPerformanceMetrics.decrypt_no_mac/1000;}

std::string TP_performance_metrics::getHeader(){
    return "encode, encrypt, serialize, store, load, deserialize, hmac, verify, encode_no_mac, encrypt_no_mac, serialize_no_mac, store_no_mac, load_no_mac, deserialize_no_mac, hkdf, decode_no_mac, decrypt_no_mac";
}

Test_Protocol::Test_Protocol(string enc_init_params_file)
{
    InitEncParams(&_enc_init_params, enc_init_params_file);
}


shared_ptr<seal_struct> Test_Protocol::set_seal_struct(){

    Servers_Protocol srvProtocol;
    shared_ptr<seal_struct> seal = srvProtocol.gen_seal_params(_enc_init_params.polyDegree, _enc_init_params.bit_sizes, _enc_init_params.scale);
    return seal;
}


void Test_Protocol::test_storage_batched_sim()
{
    // simulate the storage of secret share and 3 mac repetitions together.
    // this is used to simulate the storage speed for 16384, 98304 and 507904 items.

    int input_size[] = {16384, 98304, 507904};
    int bytes_per_secret_share = 8; // single double per secret share
    int total_mac_bytes = 3 * 8192 * 9;  // 8192 mac items. each mac item contains a double and a byte
    int num_of_repetitions = 10;
    nanoseconds store_time;
    ullong total_store_time_usecs = 0;

    // for random generation
    const char charSet[] = "0123456789abcdef";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, 15);


    int total_size = 0;

    for (int i = 0; i < sizeof(input_size)/sizeof(int); i++)
    {
        total_size = input_size[i] * bytes_per_secret_share + total_mac_bytes;
        // generate random string;
        std::string random_str(total_size, '\0');
        for (int j = 0; j < total_size; j++)
        {
            random_str[j] = charSet[distribution(generator)];
        }

        cout << "Testing " << num_of_repetitions << " repetitions for input of size: " << input_size[i] << ". Saving " << random_str.length() << " bytes to bucket" << endl;

        total_store_time_usecs = 0;

        for (int j = 0; j < num_of_repetitions; j++)
        {
            SDKOptions options;
            Aws::InitAPI(options);
            {
                S3Utility s3_utility(awsparams::region);

                high_resolution_clock::time_point start_store = utility::timer_start();
                s3_utility.save_to_bucket("save_test", awsparams::bucket_name, random_str);
                nanoseconds store_time = utility::timer_end(start_store);
                total_store_time_usecs += store_time.count() / 1000;

            }

        }

        cout << std::setprecision(32) << "Average store time: " << total_store_time_usecs / (double)num_of_repetitions << " micro seconds" <<  endl;
    }

}


void Test_Protocol::test_storage_unbatched(ullong input_size, shared_ptr<seal_struct> seal, bool with_mac, TP_performance_metrics& performanceMetrics){

    CryptoPP::AutoSeededRandomPool prng;
    byte key[KEY_SIZE_BYTES];
    prng.GenerateBlock(key, KEY_SIZE_BYTES);

    vector<double> input_vec;
    for (int i = 0; i < input_size; i++) {
            input_vec.push_back(utility::x_gen(0.0, 1.0)); //generating random input data
        }

    vector <Ciphertext> x_FHE;
    vector <Plaintext> x_pt;

    //zero local timers before each run, adding them to global timers.
    nanoseconds encode_time = nanoseconds::zero();
    nanoseconds encrypt_time =nanoseconds::zero();
    nanoseconds serialize_time =nanoseconds::zero();
    nanoseconds mac_time = nanoseconds::zero();
    nanoseconds deserialize_time =nanoseconds::zero();
    nanoseconds verify_time =nanoseconds::zero();

    for (int k = 0; k < input_size; k++){
        Plaintext plain_x;
        high_resolution_clock::time_point start_encode = utility::timer_start();
        seal->encoder_ptr->encode(input_vec[k], _enc_init_params.scale, plain_x);
        encode_time += utility::timer_end(start_encode);
        x_pt.push_back(plain_x);
    }
    performanceMetrics.encode = encode_time.count();

    for (int k = 0; k < input_size; k++){
        Ciphertext x_FHE_tmp;
        high_resolution_clock::time_point start_encrypt = utility::timer_start();
        seal->encryptor_ptr->encrypt(x_pt[k], x_FHE_tmp);
        encrypt_time += utility::timer_end(start_encrypt);
        x_FHE.push_back(x_FHE_tmp);
    }
    performanceMetrics.encrypt = encrypt_time.count();

    string str1; //string for ser ct
    string str2; //for over 1024

    for (int k = 0; k < input_size; k++){
        if(!with_mac){
            high_resolution_clock::time_point start_serialize = utility::timer_start();
            str1.append(utility::serialize_fhe(x_FHE[k]));
            serialize_time += utility::timer_end(start_serialize);
        }

        else{
            high_resolution_clock::time_point start_serialize = utility::timer_start();
            std::string cur_string = utility::serialize_fhe(x_FHE[k]);
            serialize_time += utility::timer_end(start_serialize);
            string cur_mac; //setting empty string for mac

            try
            {
                HMAC< SHA256 > hmac(key, KEY_SIZE_BYTES);

                high_resolution_clock::time_point start_mac = utility::timer_start();
                StringSource ss2(cur_string, true,
                    new HashFilter(hmac,
                        new StringSink(cur_mac)
                    ) // HashFilter
                ); // StringSource
                mac_time += utility::timer_end(start_mac);

                if( cur_mac.size()!= KEY_SIZE_BYTES) { //HMAC with SHA256 is always 256 bits, 32 bytes.
                    cout << " mac failed, mac tag size: " <<cur_mac.size() << endl;
                }
            }
            catch(const CryptoPP::Exception& e)
            {
                std::cerr << e.what() << endl;
                exit(1);
            }
            if(k<(input_size/2))
            {
                str1.append(cur_string);
                str1.append(cur_mac);
            }
            else{
                str2.append(cur_string);
                str2.append(cur_mac);
            }
        }
    }
    performanceMetrics.hmac = mac_time.count();
    performanceMetrics.serialize = serialize_time.count();

    //saving each ct size for decoding later
    vector<long> ct_size_vec;
    for (int k = 0; k < input_size; k++){
            if(!with_mac){
                ct_size_vec.push_back(utility::serialize_fhe(x_FHE[k]).size());

            }
        else{
                ct_size_vec.push_back(utility::serialize_fhe(x_FHE[k]).size()+KEY_SIZE_BYTES);
        }
    }

    //std::cout << "3 - serialized" << endl;

    SDKOptions options;
    Aws::InitAPI(options);
    {
        S3Utility s3_utility(awsparams::region);

        high_resolution_clock::time_point start_store = utility::timer_start();
        s3_utility.save_to_bucket("fhe_inputs", awsparams::bucket_name, str1);
        if(with_mac){
            s3_utility.save_to_bucket("fhe_inputs2", awsparams::bucket_name, str2);
        }
        nanoseconds store_time = utility::timer_end(start_store);
        performanceMetrics.store = store_time.count();
        //cout << "Time to STORE data " << store_time.count() << endl;
        //std::cout << "4 - saved to bucket" << endl;
    }


    long ct_size = str1.size();
    cout <<"ct_size with hmac is: "<<ct_size<<endl;
    //allocating buffer for FHE load
    char* buf = new char[ct_size];
    if (buf == NULL){
        std::cerr << "Error: Cannot allocate buffer" << endl;
        return;
    }

    long ct_size2 = str2.size();
    char* buf2;
    if(with_mac){
        cout <<"ct2_size with hmac is: "<<ct_size2<<endl;
        buf2 = new char[ct_size2];
        if (buf2 == NULL){
        std::cerr << "Error: Cannot allocate buffer2" << endl;
        return;
        }
    }

    S3Utility s3utility(awsparams::region);

    //setting timer and loading FHE block
    high_resolution_clock::time_point start_load = utility::timer_start();
    s3utility.load_from_bucket("fhe_inputs", awsparams::bucket_name,  ct_size, buf);
    if(with_mac){
        s3utility.load_from_bucket("fhe_inputs2", awsparams::bucket_name,  ct_size2, buf2);
        //cout << "loaded second input file" << endl;
    }
    nanoseconds load_time = utility::timer_end(start_load);
    performanceMetrics.load = load_time.count();
    //cout << "Time to load data " << load_time.count() << endl;

    int idx = 0; int idx2 = 0;
    vector<Ciphertext> ct_deserialized_vec;

    if(!with_mac){
        for (int k = 0; k < input_size; k++) {
            Ciphertext deserialized_ct;
            high_resolution_clock::time_point start_deserialize = utility::timer_start();
            utility::deserialize_fhe((const char*)buf+idx, ct_size_vec[k], deserialized_ct,  seal->context_ptr);
            deserialize_time += utility::timer_end(start_deserialize);

            ct_deserialized_vec.push_back(deserialized_ct);
            idx += ct_size_vec[k];
        }
        performanceMetrics.deserialize = deserialize_time.count();
    }

    else{
       //verify
        idx = 0; idx2=0;
        string cur_plain, cur_mac;
        for (int k = 0; k < input_size; k++) {
            if(k<(input_size/2)){
                string tmp_str(buf+idx, ct_size_vec[k]-KEY_SIZE_BYTES); //FHE ct is saved together with MAC, so removing tag size
                cur_plain = tmp_str;
                idx += ct_size_vec[k];
                string str(buf+idx-KEY_SIZE_BYTES, KEY_SIZE_BYTES); //MAC tag is saved at the end of the FHE ct
                cur_mac = str;
            }
            else{
                string tmp_str(buf2+idx2, ct_size_vec[k]-KEY_SIZE_BYTES); //FHE ct is saved together with MAC, so removing tag size
                cur_plain = tmp_str;
                idx2 += ct_size_vec[k];
                string str(buf2+idx2-KEY_SIZE_BYTES, KEY_SIZE_BYTES); //MAC tag is saved at the end of the FHE ct
                cur_mac = str;
            }

            //cout<<"in verify, fhe_ctxt_number: "<<k<<endl;

            HMAC< SHA256 > hmac(key, KEY_SIZE_BYTES);
            const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

            high_resolution_clock::time_point start_verify = utility::timer_start();
            StringSource(cur_plain + cur_mac, true,
                new HashVerificationFilter(hmac, NULL, flags)
            ); // StringSource
            verify_time += utility::timer_end(start_verify);
        }
        //cout << "verified data "  << endl;
        performanceMetrics.verify = verify_time.count();
        idx = 0; idx2=0;

        for (int k = 0; k < input_size/2; k++) {
            Ciphertext deserialized_ct;
            high_resolution_clock::time_point start_deserialize = utility::timer_start();
            utility::deserialize_fhe((const char*)buf+idx, ct_size_vec[k]-KEY_SIZE_BYTES, deserialized_ct,  seal->context_ptr);
            deserialize_time += utility::timer_end(start_deserialize);
            idx += ct_size_vec[k];
            ct_deserialized_vec.push_back(deserialized_ct);

            }
        for (int k = input_size/2; k < input_size; k++) {
            Ciphertext deserialized_ct;
            high_resolution_clock::time_point start_deserialize = utility::timer_start();
            //cout<<"in second option k>=(input_size/2)" <<endl;
            utility::deserialize_fhe((const char*)buf2+idx2, ct_size_vec[k]-KEY_SIZE_BYTES, deserialized_ct,  seal->context_ptr);
            deserialize_time += utility::timer_end(start_deserialize);
            idx2 += ct_size_vec[k];
            ct_deserialized_vec.push_back(deserialized_ct);
            }

        }
        performanceMetrics.deserialize = deserialize_time.count();
        //cout << "6 - deserialized data "  << endl;

        vector<double> output_vec;
        //decoding decrypting for tests
        for (int k = 0; k < input_size; k++) {
            vector<double> cur_res;
            Plaintext pt;
            seal->decryptor_ptr->decrypt(ct_deserialized_vec[k], pt);
            seal->encoder_ptr->decode(pt, cur_res);
            output_vec.push_back(cur_res[0]);
        }

        int counter=0;
        for( int h=0; h<input_size; h++){
                if( abs(input_vec[h] - output_vec[h] )>0.01){
                    counter++;
                    if(counter>10){
                        exit(1);
                    }
                    cout<< "error decrypting at index "<<h<<endl;
                    cout << "output_vec[h] " << output_vec[h] << endl;
                    cout << "input_vec[h] " <<input_vec[h] << endl;
                }
            }



        delete buf;
        delete buf2;
        Aws::ShutdownAPI(options);
    //cout << "after delete " <<  endl;

}


void Test_Protocol::hmac_on_FHE(ullong input_size, shared_ptr<seal_struct> seal, TP_performance_metrics& performanceMetrics){

    //zero out all timers which are being added to in each run
    performanceMetrics.serialize = 0;
    performanceMetrics.hmac = 0;
    performanceMetrics.verify = 0;

    CryptoPP::AutoSeededRandomPool prng;
    byte key[KEY_SIZE_BYTES];
    prng.GenerateBlock(key, KEY_SIZE_BYTES);

   vector <vector<double>> main_vec;

    int max_ct_entries = _enc_init_params.polyDegree/2;
    if(input_size<max_ct_entries){
        max_ct_entries= input_size;
    }

    std::string str1;
    int fhe_ctxt_number = ceil((input_size + 0.0) / max_ct_entries);

    vector<long> ct_size_vec;

    for (int k = 0; k < fhe_ctxt_number; k++) {
        vector<double> input_vec= utility::x_gen_int(0, _enc_init_params.prime_minus_1, max_ct_entries);
        main_vec.push_back(input_vec);
    }

    //encode and encrypt
    vector <Ciphertext> x_FHE;
    vector <Plaintext> x_pt;

    high_resolution_clock::time_point start_encode = utility::timer_start();
    for (int k = 0; k < fhe_ctxt_number; k++){
        Plaintext plain_x;
        seal->encoder_ptr->encode(main_vec[k], _enc_init_params.scale, plain_x);
        x_pt.push_back(plain_x);
    }
    nanoseconds encode_time = utility::timer_end(start_encode);
    performanceMetrics.encode = encode_time.count();

    high_resolution_clock::time_point start_encrypt = utility::timer_start();
    for (int k = 0; k < fhe_ctxt_number; k++){
        Ciphertext x_FHE_tmp;
        seal->encryptor_ptr->encrypt(x_pt[k], x_FHE_tmp);
        x_FHE.push_back(x_FHE_tmp);
    }
    nanoseconds encrypt_time = utility::timer_end(start_encrypt);
    performanceMetrics.encrypt = encrypt_time.count();

    string tmp_str;

    for (int k = 0; k < fhe_ctxt_number; k++){
        //str1.append(utility::serialize_fhe(x_FHE[k]));
        high_resolution_clock::time_point start_serialize = utility::timer_start();
        std::string cur_string = utility::serialize_fhe(x_FHE[k]);
        nanoseconds serialize_time = utility::timer_end(start_serialize);
        performanceMetrics.serialize += serialize_time.count();

        string cur_mac; //setting empty string for mac

        try
        {
            HMAC< SHA256 > hmac(key, KEY_SIZE_BYTES);//init hmac
            high_resolution_clock::time_point hmac_time = utility::timer_start();

            //apply hmac
            StringSource ss2(cur_string, true,
                new HashFilter(hmac,
                    new StringSink(cur_mac)
                ) // HashFilter
            ); // StringSource
            auto durtion_hmac_time = utility::timer_end(hmac_time);
            performanceMetrics.hmac += durtion_hmac_time.count();

            if( cur_mac.size()!= KEY_SIZE_BYTES) { //HMAC with SHA256 is always 256 bits, 32 bytes.
                cout << " mac failed, mac tag size: " <<cur_mac.size() << endl;
            }
        }
        catch(const CryptoPP::Exception& e)
        {
            std::cerr << e.what() << endl;
            exit(1);
        }

        high_resolution_clock::time_point finish_serialize = utility::timer_start();
        str1.append(cur_string);
        str1.append(cur_mac);
        nanoseconds finish_serialize_time = utility::timer_end(finish_serialize);
        performanceMetrics.serialize += finish_serialize_time.count();

    }

    //getting exact size for each ct
    for (int k = 0; k < fhe_ctxt_number; k++){
        ct_size_vec.push_back(utility::serialize_fhe(x_FHE[k]).size()+KEY_SIZE_BYTES);
    }

    //std::cout << "3 - serialized" << endl;

    SDKOptions options;
    Aws::InitAPI(options);
    {
        S3Utility s3_utility(awsparams::region);

        high_resolution_clock::time_point start_store = utility::timer_start();
        s3_utility.save_to_bucket("fhe_inputs", awsparams::bucket_name, str1);
        nanoseconds store_time = utility::timer_end(start_store);
        performanceMetrics.store = store_time.count();
        //std::cout << "4 - saved to bucket" << endl;
    }

    long ct_size = str1.size();
    cout <<"ct size w hmac is: "<<ct_size<<endl;
    //allocating buffer for FHE load
    char* buf = new char[ct_size];
    if (buf == NULL){
        std::cerr << "Error: Cannot allocate buffer" << endl;
        return;
    }

    S3Utility s3utility(awsparams::region);

    //setting timer and loading FHE block
    high_resolution_clock::time_point start_load = utility::timer_start();
    s3utility.load_from_bucket("fhe_inputs", awsparams::bucket_name,  ct_size, buf);
    //cout << "Input buf is "  << buf << endl;
    nanoseconds load_time = utility::timer_end(start_load);
    performanceMetrics.load = load_time.count();

   //verify
   int idx = 0;
    for (int k = 0; k < fhe_ctxt_number; k++) {
        string cur_plain(buf+idx, ct_size_vec[k]-KEY_SIZE_BYTES); //FHE ct is saved together with MAC, so removing tag size
        idx += ct_size_vec[k];
        string cur_mac(buf+idx-KEY_SIZE_BYTES, KEY_SIZE_BYTES); //MAC tag is saved at the end of the FHE ct

        //cout<<"fhe_ctxt_number: "<<k<<endl;

        HMAC< SHA256 > hmac(key, KEY_SIZE_BYTES);
        const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

        high_resolution_clock::time_point verify_time = utility::timer_start();
        StringSource(cur_plain + cur_mac, true,
            new HashVerificationFilter(hmac, NULL, flags)
        ); // StringSource

        auto durtion_verify_time = utility::timer_end(verify_time);
        performanceMetrics.verify += durtion_verify_time.count();
   }

    idx = 0;
    vector<Ciphertext> ct_deserialized_vec;
    vector<vector<double>> output_vec;

    high_resolution_clock::time_point start_deserialize = utility::timer_start();
    for (int k = 0; k < fhe_ctxt_number; k++) {
        Ciphertext deserialized_ct;
        utility::deserialize_fhe((const char*)buf+idx, ct_size_vec[k]-KEY_SIZE_BYTES, deserialized_ct,  seal->context_ptr);
        ct_deserialized_vec.push_back(deserialized_ct);
        idx += ct_size_vec[k];
    }
    nanoseconds duration_deserialize_time = utility::timer_end(start_deserialize);
    performanceMetrics.deserialize = duration_deserialize_time.count();

    //decoding decrypting for tests
    for (int k = 0; k < fhe_ctxt_number; k++) {
        vector<double> tmp_vec;
        Plaintext pt;
        seal->decryptor_ptr->decrypt(ct_deserialized_vec[k], pt);
        seal->encoder_ptr->decode(pt, tmp_vec);
        output_vec.push_back(tmp_vec);
    }

    int counter=0;
    for( int h=0; h<fhe_ctxt_number; h++){
        for (int j = 0; j <max_ct_entries ; j++) {
            if( abs(main_vec[h][j] - output_vec[h][j] )>0.01){
                counter++;
                if(counter>10){
                    exit(1);
                }
                cout<< "error decrypting at index "<<j <<endl;
                cout << "output_vec[h][j] " << output_vec[h][j] << endl;
                cout << "main_vec[h][j] " <<main_vec[h][j] << endl;
            }
        }
    }
    delete buf;
    Aws::ShutdownAPI(options);
}


int Test_Protocol::test_compact_HE_mac_optimized(ullong input_size){

    vector<vector<double>> x_int_vec, x_frac_vec;
    int N_agg = ceil((input_size+0.0)/_enc_init_params.max_ct_entries);

    MAC mac(_enc_init_params);

    vector<Batched_Key_Generator> kmac_vec;
    int len_vec = std::min(int(input_size), _enc_init_params.max_ct_entries);
    int last_vec_size = (input_size%_enc_init_params.max_ct_entries == 0) ? len_vec : input_size % _enc_init_params.max_ct_entries;
    //cout <<"N_agg: "<<N_agg << " len_vec: "<<len_vec<<endl;

    //generating random input vectors (outputs of secret sharing) and key mac
    for(int j=0; j<N_agg; j++)
    {
        int len = len_vec;
        if(j==(N_agg-1))
        {
            len = last_vec_size;
        }
        vector<double> x_int = utility::x_gen_int(0, 1, len);
        vector<double> x_frac = utility::x_gen_int(0, _enc_init_params.prime_minus_1, len);

        x_int_vec.push_back(x_int);
        x_frac_vec.push_back(x_frac);

        Batched_Key_Generator kmac(_enc_init_params.prime);
        vector<double> a_int = utility::x_gen_int(0, 1, len_vec); //generating random bit vec
        vector<double> a_frac = utility::x_gen_int(0,  _enc_init_params.prime_minus_1, len_vec);
        kmac.a_int = a_int;
        kmac.a_frac = a_frac;

        if(j==0){ //other values than a int, a frac are only necessary for number of slot count
            kmac.b = utility::x_gen_int(0, _enc_init_params.prime_minus_1, len_vec);//utility::x_gen_int(0, _enc_init_params.prime_minus_1, 1)[0];
            kmac.c_alpha = utility::x_gen_int(0, _enc_init_params.prime_minus_1, len_vec);
            kmac.c_beta = utility::x_gen_int(0, _enc_init_params.prime_minus_1, len_vec);
            kmac.d_alpha=utility::x_gen_int(0, 1, len_vec); //generating random bit vec
            kmac.d_beta=utility::x_gen_int(0, 1, len_vec); //generating random bit vec
        }

        kmac_vec.push_back(kmac);
    }

    /*
    //test values prints
    cout << "x_int[0]: " << x_int_vec[0][0] << " x_frac[0]: " << x_frac_vec[0][0] << endl;
    cout << "a_int[0]: " <<kmac_vec[0].a_int[0] << " a_frac[0]: " <<kmac_vec[0].a_frac[0] <<" kmac.b: "<<kmac_vec[0].b[0]<<" kmac.c_alpha: "<<kmac_vec[0].c_alpha[0] << " kmac.c_beta: " <<kmac_vec[0].c_beta[0] <<endl;
    cout << "d_alpha[0]: " << kmac_vec[0].d_alpha[0] << " d_beta[0]: " << kmac_vec[0].d_beta[0] << endl;
    */

    //starting MAC computation
    double prime_square = pow(_enc_init_params.prime, 2);
    mac_tag_batched_optimized optimized_mac;
	int num_of_secret_shares = input_size;
	vector<double> result_vec(len_vec, 0.0); //always has to be longest vector //changed from slot count - TODO: change origin.

    for(int j=0; j<N_agg; j++){
        // calculate x_int * a_int + x_frac * a_frac and then add to the result vector

        int len = len_vec;
        if(j==(N_agg-1))
        {
            len = last_vec_size;
        }
        vector<double> x_int_for_mac(len, 0.0);
        vector<double>  x_frac_for_mac(len, 0.0);

        std::transform(x_int_vec[j].begin(), x_int_vec[j].end(), kmac_vec[j].a_int.begin(), x_int_for_mac.begin(), std::multiplies<double>());
        std::transform(x_frac_vec[j].begin(), x_frac_vec[j].end(), kmac_vec[j].a_frac.begin(), x_frac_for_mac.begin(), std::multiplies<double>());
        std::transform(x_int_for_mac.begin(), x_int_for_mac.end(), x_frac_for_mac.begin(), x_int_for_mac.begin(), std::plus<double>());
        std::transform(result_vec.begin(), result_vec.end(), x_int_for_mac.begin(), result_vec.begin(), std::plus<double>());

    }

    // add b to the sum of (x_int * a_int + x_frac * a_frac)
    std::transform(result_vec.begin(), result_vec.end(), kmac_vec[0].b.begin(), result_vec.begin(), std::plus<double>());
    optimized_mac = mac.compact_mac_batched_optimized(kmac_vec[0], result_vec);

    vector<double> alpha_int_vec, beta_int_vec;
    //mac tag part two - seperate to y_beta_int, y_alpha_int and encrypt
    for(int i=0; i<optimized_mac.mac_part2.size(); i++){

        unsigned char val = optimized_mac.mac_part2[i];
        double pSquare = pow(_enc_init_params.prime, 2);
        double pTriple = pow(_enc_init_params.prime, 3);

        double alpha_int = (((int)val >> 1) & 0x1) * pTriple;
        double beta_int = ((int)val & 0x1) * pSquare;

        /*
        cout.precision(15);
        cout <<"for i: " <<i <<" alpha_int: " <<alpha_int << " beta_int: "<<beta_int<<endl;
        cout <<"optimized_mac.mac_part1[i]: " <<optimized_mac.mac_part1[i]<<endl; */

        alpha_int_vec.push_back(alpha_int);
        beta_int_vec.push_back(beta_int);
    }

    //aux encryptions
    shared_ptr<seal_struct> seal_struct = set_seal_struct();
    Plaintext pt_t_r, pt_alpha_int, pt_beta_int;
    Ciphertext ct_t_r, ct_alpha_int, ct_beta_int;

    seal_struct->encoder_ptr->encode(optimized_mac.mac_part1, _enc_init_params.scale, pt_t_r);
    seal_struct->encryptor_ptr->encrypt(pt_t_r, ct_t_r);

    seal_struct->encoder_ptr->encode(alpha_int_vec, _enc_init_params.scale, pt_alpha_int);
    seal_struct->encryptor_ptr->encrypt(pt_alpha_int, ct_alpha_int);
    seal_struct->encoder_ptr->encode(beta_int_vec, _enc_init_params.scale, pt_beta_int);
    seal_struct->encryptor_ptr->encrypt(pt_beta_int, ct_beta_int);

    Ciphertext batched_y_ct;
    for(int j=0; j<N_agg; j++){
        Plaintext pt_x_int_const, pt_x_frac_const;
        Ciphertext ct_x_int_const, ct_x_frac_const;

        seal_struct->encoder_ptr->encode(x_int_vec[j], _enc_init_params.scale, pt_x_int_const);
        seal_struct->encryptor_ptr->encrypt(pt_x_int_const, ct_x_int_const);

        seal_struct->encoder_ptr->encode(x_frac_vec[j], _enc_init_params.scale, pt_x_frac_const);
        seal_struct->encryptor_ptr->encrypt(pt_x_frac_const, ct_x_frac_const);

        //verify by DS
        if(j==0){
            batched_y_ct = verifyHE_batched_y(seal_struct, kmac_vec[j], ct_x_int_const, ct_x_frac_const);
        }
        else{ // this is adds a_int*x_int + a_frac*x_frac values calculated earlier to all the same values from the previous ciphertexts
            Ciphertext batched_y_ct_temp = verifyHE_batched_y(seal_struct, kmac_vec[j], ct_x_int_const, ct_x_frac_const);
            seal_struct->evaluator_ptr->mod_switch_to_inplace(batched_y_ct, batched_y_ct_temp.parms_id());
            seal_struct->evaluator_ptr->add_inplace(batched_y_ct, batched_y_ct_temp);
        }

    }
    Ciphertext batched_y_tag_ct = verifyHE_batched_y_tag(seal_struct, len_vec, kmac_vec[0], ct_t_r, ct_alpha_int, ct_beta_int);

    Ciphertext diff_ct;
    vector<Ciphertext>(diffCt_shared);
    seal_struct->evaluator_ptr->sub(batched_y_ct, batched_y_tag_ct, diff_ct);
    diffCt_shared.push_back(diff_ct);

    return test_correctness::is_MAC_HE_valid(seal_struct,  make_shared<vector<Ciphertext>>(diffCt_shared), input_size, _enc_init_params.max_ct_entries, "MAC batched scheme", true);

}


Ciphertext Test_Protocol::verifyHE_batched_y(const shared_ptr<seal_struct> seal_struct , Batched_Key_Generator kmac, Ciphertext ct_x_int, Ciphertext ct_x_frac){

    MAC mac(_enc_init_params);
    Ciphertext ct_result;
    Plaintext pt_a_int, pt_a_frac;

	seal_struct->encoder_ptr->encode(kmac.a_int, _enc_init_params.scale, pt_a_int);
	seal_struct->encoder_ptr->encode(kmac.a_frac, _enc_init_params.scale, pt_a_frac);

	mac.mult_ct_pt_inplace(seal_struct, ct_x_int, pt_a_int);
	mac.mult_ct_pt_inplace(seal_struct, ct_x_frac, pt_a_frac);

	seal_struct->evaluator_ptr->add(ct_x_int, ct_x_frac, ct_result);

    return ct_result;
}


Ciphertext Test_Protocol::verifyHE_batched_y_tag(const shared_ptr<seal_struct> seal_struct , int len_vec, Batched_Key_Generator kmac, Ciphertext ct_tr, Ciphertext ct_alpha_int, Ciphertext ct_beta_int){

    MAC mac(_enc_init_params);
    double p_square = _enc_init_params.prime * _enc_init_params.prime;
	double p_triple = p_square * _enc_init_params.prime;
	vector<double> signPTriple(len_vec, 1); //if d=0 then: (-1)^d *p^3 = p^2
	vector<double> signPSquare(len_vec, 1); //if d=0 then: (-1)^d *p^2 = p^3
	vector<double> cleartext_calc(len_vec, 0); //vector to sum all cleartext operations in verify

    for (int i = 0; i < len_vec; i++)
    {
		if (kmac.d_alpha[i] == 1) {
			signPTriple[i] = -1; // if d=1 then: (-1)^d_alpha *p^3 = -p^3
			cleartext_calc[i] += p_triple - kmac.c_alpha[i] * p_square; // (-1)^d_alpha*(-d_alpha)*p^3-c_alpha*p^2
		}
		else {//d=0
			cleartext_calc[i] +=  - kmac.c_alpha[i]* p_square ;//if d=0: -c_alpha*p^2
		}

		if (kmac.d_beta[i] == 1) {
			signPSquare[i] = -1; // if d=1 then: (-1)^d_beta *p^2 = -p^2
			cleartext_calc[i] += p_square - kmac.c_beta[i] * _enc_init_params.prime ; // (-1)^d_beta*(-d_beta)*p^2-c_beta*p
		}
		else {//d=0
			cleartext_calc[i] +=  - kmac.c_beta[i] * _enc_init_params.prime ;//if d=0: -c_beta*p
		}

		cleartext_calc[i] -= kmac.b[i];
	}

    Plaintext pt_signPTriple, pt_signPSquare, cleartext_calc_pt;
	seal_struct->encoder_ptr->encode(signPTriple, _enc_init_params.scale, pt_signPTriple);
	seal_struct->encoder_ptr->encode(signPSquare, _enc_init_params.scale, pt_signPSquare);

	Ciphertext y_comp;

	mac.mult_ct_pt_inplace(seal_struct, ct_alpha_int, pt_signPTriple); //(-1)^d_alpha*p^3* y_alpha_int
	mac.mult_ct_pt_inplace(seal_struct, ct_beta_int, pt_signPSquare); //(-1)^d_beta*p^2* y_beta_int
    seal_struct->evaluator_ptr->add(ct_alpha_int, ct_beta_int, y_comp); //(-1)^d_alpha*p^3* y_alpha_int + (-1)^d_beta*p^2* y_beta_int

	seal_struct->evaluator_ptr->mod_switch_to_inplace(ct_tr, y_comp.parms_id());
	seal_struct->evaluator_ptr->add_inplace(y_comp, ct_tr); //(-1)^d_alpha*p^3* y_alpha_int + (-1)^d_beta*p^2* y_beta_int+y_t

    seal_struct->encoder_ptr->encode(cleartext_calc, y_comp.parms_id(), _enc_init_params.scale, cleartext_calc_pt);
	seal_struct->evaluator_ptr->add_plain_inplace(y_comp, cleartext_calc_pt);


	return y_comp;
}


void Test_Protocol::test_hkdf(TP_performance_metrics& performanceMetrics){
	using namespace CryptoPP;
	// Define parameters
	byte ikm[32] =
	{0x00, 0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08, 0x09,
	0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
	0x0F, 0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
	std::string info = "Example HKDF Info";
	byte derivedKey[32]; // Length of derived key

	// Create the HKDF object
	HKDF<SHA256> hkdf;

	// Derive the key with an empty salt (equivalent to all-zero salt)
    high_resolution_clock::time_point time_hkdf= utility::timer_start();
	hkdf.DeriveKey(derivedKey, sizeof(derivedKey), ikm, sizeof(ikm), nullptr, 0, (const byte*)info.data(), info.size());
    performanceMetrics.hkdf = utility::timer_end(time_hkdf).count();

	// Print the derived key in hexadecimal format
	std::string encoded;
	HexEncoder encoder(new StringSink(encoded));
	encoder.Put(derivedKey, sizeof(derivedKey));
	encoder.MessageEnd();
	//std::cout << "Derived Key: " << encoded << std::endl;

}


void Test_Protocol::test_crypto_sink_hmac(TP_performance_metrics& performanceMetrics){

    const byte k[] = {
        0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    string plain = "Example HMAC plain";
    string mac, encoded;

    // Pretty print key
    encoded.clear();
    CryptoPP::StringSource ss1(k, sizeof(k), true,
        new HexEncoder(new StringSink(encoded)) ); // HexEncoder StringSource

    //cout << "key: " << encoded << endl;
    //cout << "plain text: " << plain << endl;

    try
    {
        high_resolution_clock::time_point init_hmac = utility::timer_start();
        CryptoPP::HMAC< SHA256 > hmac(k, sizeof(k));
        nanoseconds hmac_time = utility::timer_end(init_hmac);

        high_resolution_clock::time_point update_hmac = utility::timer_start();
        StringSource ss2(plain, true,
            new HashFilter(hmac, new StringSink(mac) ) ); // HashFilter// StringSource
        performanceMetrics.hmac = utility::timer_end(update_hmac).count();

        //cout << "hmac len : "<<mac.size()<< " data: " << mac << endl;

    }
    catch(const CryptoPP::Exception& e)
    {
        std::cerr << e.what() << endl;
        exit(1);
    }
    mac.clear();

    // Pretty print
    encoded.clear();
    StringSource ss3(mac, true,
        new HexEncoder( new StringSink(encoded)) ); // HexEncoder // StringSource

    //cout << "hmac len : "<<encoded.size()<< " data: " << encoded << endl;
}

/////////////////////////////////////////////////////


int test_correctness::is_correct_secret_sharing(shared_ptr<vector<Ciphertext>> x_final_CT, shared_ptr<seal_struct> seal, const vector<double>& x_origin,
                                     int input_size, int max_ct_entries)
{
    int fhe_ctxt_number = ceil((input_size + 0.0) / max_ct_entries); //number of FHE  ciphertexts, derived automatically from user input

    vector<vector<double>> main_final_x;

    cout << "Checking secret share correctness" << endl;
	//decrypt and decode final output
	for (int i = 0; i < fhe_ctxt_number; i++)
	{
		Plaintext plain;
		vector<double> final_x;
		seal->decryptor_ptr->decrypt(x_final_CT.get()->at(i), plain);
		seal->encoder_ptr->decode(plain, final_x);
		main_final_x.push_back(final_x);
	}
	//check if output equals input
	int counter_incorrect =0;
	int threshold = 1;
	for (int i = 0; (i < fhe_ctxt_number); i++)
	{
        for (int j = 0; j < max_ct_entries && ((j + i * max_ct_entries) < input_size) && (counter_incorrect < constants::max_reported_incorrect_items); j++)
		{
		    double orig_val = x_origin[j + i * max_ct_entries];
		    double calc_val = main_final_x[i][j];

            if (abs(orig_val - calc_val) > threshold){
                cout << "incorrect " << endl;
				counter_incorrect++; //in case of final digit affects intire num
				cout << "CT index is: " << i << " datapoint index " << j << " origin is " << orig_val << " result is " << calc_val << endl;
			}

		}
	}

	if (counter_incorrect > 0)
    {
        cout << "Secret share incorrect count: " << counter_incorrect << endl;
        if (counter_incorrect >= constants::max_reported_incorrect_items)
        {
            cout << "Note that incorrect amounts larger than " << constants::max_reported_incorrect_items << " will not be reported" << endl;
        }
    }
    else
    {
        cout << "Secret share check for " << input_size << " inputs - PASSED!" << endl;
    }

	return 1;
}



bool test_correctness::is_MAC_HE_valid(shared_ptr<seal_struct> seal_struct, shared_ptr<vector<Ciphertext>> diffCt, int input_size, int max_ct_entries, string mac_type, bool compactMac)
{

    int fhe_ctxt_number = ceil((input_size + 0.0) / max_ct_entries); //number of FHE  ciphertexts, derived automatically from user input
    if(compactMac){
        fhe_ctxt_number =1;
    }

    bool correct = true;
    int EPSILON = 1;
    int counter_incorrect = 0;

    cout << "Checking " << mac_type << " MAC correctness" << endl;
    //decrypt and decode output for comparison on cleartext
    for (int i = 0; i < fhe_ctxt_number; i++)
	{
        Plaintext pt_diff;
        vector<double> diff_vec;
        seal_struct->decryptor_ptr->decrypt(diffCt.get()->at(i), pt_diff);
        seal_struct->encoder_ptr->decode(pt_diff, diff_vec);


        for (int j = 0; (j < max_ct_entries) && ((j + i * max_ct_entries) < input_size) && (counter_incorrect < constants::max_reported_incorrect_items);  j++) {
            bool equal = (abs(diff_vec[j]) < EPSILON);
            //cout <<"diff_vec[j]: "<<diff_vec[j]<<endl;
            if (equal != true)
            {
                cout.precision(14);
                std::cout << " ERROR at cipher: "<<i <<" index "<< j << " diff is: " << diff_vec[j] << endl;
                correct = false;
                counter_incorrect+=1;
            }
        }
	}

    if (counter_incorrect > 0)
    {
        cout << "MAC incorrect count: " << counter_incorrect << endl;
        if (counter_incorrect >= constants::max_reported_incorrect_items)
        {
            cout << "Note that incorrect amounts larger than " << constants::max_reported_incorrect_items << " will not be reported" << endl;
        }
    }
    else
    {
        cout << "MAC check for " << input_size << " inputs - PASSED!" << endl;
    }


    return correct;
}


bool test_correctness::is_MAC_PT_valid(vector<double> diff_vec, int input_size, int max_ct_entries, string mac_type)
{

    int fhe_ctxt_number = ceil((input_size + 0.0) / max_ct_entries); //number of FHE  ciphertexts, derived automatically from user input
    bool correct = true;
    int EPSILON = 1;
    int counter_incorrect = 0;

    cout << "Checking " << mac_type << " MAC correctness" << endl;
    for (int i = 0; i < fhe_ctxt_number; i++)
	{

        for (int j = 0; (j < max_ct_entries) && ((j + i * max_ct_entries) < input_size) && (counter_incorrect < constants::max_reported_incorrect_items);  j++) {
            bool equal = (abs(diff_vec[j]) < EPSILON);
            //cout <<"diff_vec[j]: "<<diff_vec[j]<<endl;
            if (equal != true)
            {
                cout.precision(14);
                std::cout << " ERROR at cipher: "<<i <<" index "<< j << " diff is: " << diff_vec[j] << endl;
                correct = false;
                counter_incorrect+=1;
            }
        }
	}

    if (counter_incorrect > 0)
    {
        cout << "MAC incorrect count: " << counter_incorrect << endl;
        if (counter_incorrect >= constants::max_reported_incorrect_items)
        {
            cout << "Note that incorrect amounts larger than " << constants::max_reported_incorrect_items << " will not be reported" << endl;
        }
    }
    else
    {
        cout << "MAC cleartext check passed for " << input_size << " inputs" << endl;
    }


    return correct;
}


