#include "Key_Generator.h"

// Constructor
Key_Generator::Key_Generator(ullong prime)
{
    _prime = prime;
}

// Destructor
Key_Generator::~Key_Generator()
{
    // dtor
}

// Derive vectors a, b, c_alpha, d_alpha using HMAC and derived keys
void Key_Generator::derive_abcd(CryptoPP::HMAC<SHA256>& hmac, std::string key, ullong start_index, ullong amount)
{
    for (int i = 0; i < amount; i++)
    {
        std::string derivation_data = key + std::to_string(start_index);
        std::string derived_key = derive_rand_key(hmac, derivation_data);

        ullong a1_int = (((ullong)derived_key[0]  << 48) | ((ullong)derived_key[1]  << 40) | ((ullong)derived_key[2]  << 32) |
                         ((ullong)derived_key[3]  << 24) | ((ullong)derived_key[4]  << 16) | ((ullong)derived_key[5]  << 8)  |
                         (ullong)(derived_key[6]));

        ullong a1_frac = (((ullong)derived_key[7]  << 48) | ((ullong)derived_key[8]  << 40) | ((ullong)derived_key[9]  << 32) |
                          ((ullong)derived_key[10] << 24) | ((ullong)derived_key[11] << 16) | ((ullong)derived_key[12] << 8)  |
                          (ullong)(derived_key[13]));

        ullong b1 = (((ullong)derived_key[24] << 48) | ((ullong)derived_key[25] << 40) | ((ullong)derived_key[26] << 32) |
                     ((ullong)derived_key[27] << 24) | ((ullong)derived_key[28] << 16) | ((ullong)derived_key[29] << 8)  |
                     (ullong)(derived_key[30]));

        ullong c1 = (((ullong)derived_key[14] << 48) | ((ullong)derived_key[15] << 40) | ((ullong)derived_key[16] << 32) |
                     ((ullong)derived_key[17] << 24) | ((ullong)derived_key[18] << 16) | ((ullong)derived_key[19] << 8)  |
                     (ullong)(derived_key[20]));

        a_int.push_back(fmod(a1_int, _prime));
        a_frac.push_back(fmod(a1_frac, _prime));
        b.push_back(fmod(b1, _prime));
        c_alpha.push_back(fmod(c1, _prime));
        d_alpha.push_back(((unsigned int)(derived_key[31]) % 2));

        start_index++;
    }
}

// Derive a random key using HMAC
std::string Key_Generator::derive_rand_key(CryptoPP::HMAC<SHA256> hmac, std::string derivation_data)
{
    std::string mac;
    StringSource ss2(derivation_data, true,
                     new HashFilter(hmac, new StringSink(mac)));

    if (mac.size() != KEY_SIZE_BYTES)
    {
        throw std::runtime_error("Derivation failed - length not as expected");
    }

    return mac;
}

// Derive random keys using HKDF and append to keys vector
void Key_Generator::derive_rand_key_hkdf(byte* key_tag, int key_tag_len, std::string info, std::vector<byte>& keys, int key_len)
{
    CryptoPP::HKDF<SHA512> hkdf;
    int max_derived_key_len = hkdf.MaxDerivedKeyLength();
    byte derivedKey[max_derived_key_len];

    int num_of_derivations = key_len / max_derived_key_len;
    int remainder = key_len % max_derived_key_len;
    int i = 0;

    for (i = 0; i < num_of_derivations; i++)
    {
        std::string cur_derivation_data = info + std::to_string(i);
        hkdf.DeriveKey(derivedKey, max_derived_key_len, key_tag, key_tag_len, NULL, 0, (byte*)cur_derivation_data.c_str(), cur_derivation_data.length());
        std::copy(&derivedKey[0], &derivedKey[max_derived_key_len], std::back_inserter(keys));
    }

    if (remainder)
    {
        std::string cur_derivation_data = info + std::to_string(i);
        hkdf.DeriveKey(derivedKey, sizeof(derivedKey), key_tag, key_tag_len, NULL, 0, derivedKey, max_derived_key_len);
        std::copy(derivedKey, derivedKey + remainder, std::back_inserter(keys));
    }
}


// Batched_Key_Generator constructor (inherits Key_Generator)
Batched_Key_Generator::Batched_Key_Generator(ullong prime) : Key_Generator(prime)
{}


// SHARE_MAC_KEYS constructor
SHARE_MAC_KEYS::SHARE_MAC_KEYS(int key_length)
{
    key_len = key_length;
    keys_iter = 0;
    keys.reserve(key_len);
}

// SHARE_MAC_KEYS destructor
SHARE_MAC_KEYS::~SHARE_MAC_KEYS()
{}

// Generate keys using HKDF with provided key tag and info
void SHARE_MAC_KEYS::gen_keys(byte* key_tag, int key_tag_len, std::string info)
{
    Key_Generator k_mac; // default prime not used here
    k_mac.derive_rand_key_hkdf(key_tag, key_tag_len, info, keys, key_len);
}

// Return next byte from keys vector; exit if exceeded
byte SHARE_MAC_KEYS::get_next_byte(void)
{
    if (keys_iter < key_len)
    {
        return keys[keys_iter++];
    }

    perror("Key iterator exceeded key array size");
    cout << "key length: " << key_len << " keys_iter: " << keys_iter << endl;
    exit(1);
}

// Derive a_int and a_frac values for a batch
void Batched_Key_Generator::derive_a(SHARE_MAC_KEYS* kmac_keys, ullong start_index, ullong ct_max_index, int bytes_per_a)
{
    for (int i = start_index; i < start_index + ct_max_index; i++)
    {
        ullong a1_int = 0;
        ullong a1_frac = 0;

        for (int j = 0; j < bytes_per_a; j++)
        {
            a1_int |= ((ullong)kmac_keys->get_next_byte() << 8 * j);
            a1_frac |= ((ullong)kmac_keys->get_next_byte() << 8 * j);
        }

        a_int.push_back(fmod(a1_int, _prime));
        a_frac.push_back(fmod(a1_frac, _prime));
    }
}

// Derive b, c_alpha, c_beta, d_alpha, d_beta values for a batch
void Batched_Key_Generator::derive_bcd(SHARE_MAC_KEYS* kmac_keys, int amount, int bytes_per_bc, int start_iter_index)
{
    int curr_iter = kmac_keys->keys_iter;
    kmac_keys->keys_iter = start_iter_index;

    for (int i = 0; i < amount; i++)
    {
        ullong b1 = 0;
        ullong c1_alpha = 0;
        ullong c1_beta = 0;
        byte d1;

        for (int j = 0; j < bytes_per_bc; j++)
        {
            b1 |= ((ullong)kmac_keys->get_next_byte() << 8 * j);
            c1_alpha |= ((ullong)kmac_keys->get_next_byte() << 8 * j);
            c1_beta |= ((ullong)kmac_keys->get_next_byte() << 8 * j);
        }

        d1 = kmac_keys->get_next_byte();

        b.push_back(fmod(b1, _prime));
        c_alpha.push_back(fmod(c1_alpha, _prime));
        c_beta.push_back(fmod(c1_beta, _prime));
        d_alpha.push_back(d1 & 0x1);
        d_beta.push_back(d1 & 0x2);
    }

    kmac_keys->keys_iter = curr_iter;
}
