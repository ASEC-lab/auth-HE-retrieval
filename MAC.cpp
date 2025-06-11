#include "MAC.h"
#include <random>
#include <chrono>

using namespace utility;

/**
 * Constructor
 */
MAC::MAC(enc_init_params_s enc_init_params)
{
    _enc_init_params = enc_init_params;
}

/**
 * Multiply Ciphertext by Plaintext in-place with rescaling and setting scale.
 */
Ciphertext& MAC::mult_ct_pt_inplace(const shared_ptr<seal_struct> seal_struct, Ciphertext& ct, const Plaintext& pt)
{
    seal_struct->evaluator_ptr->multiply_plain_inplace(ct, pt);
    seal_struct->evaluator_ptr->rescale_to_next_inplace(ct);
    ct.scale() = _enc_init_params.scale;
    return ct;
}

/**
 * Derive Key_Generator for compact MAC (unbatched) using HMAC.
 */
Key_Generator MAC::Derive_compact_kmac_unbatched_single(CryptoPP::HMAC<SHA256>& hmac, ullong start_index, ullong amount)
{
    std::string derivation_data("storage_test_MAC_");

    Key_Generator kmac(_enc_init_params.prime);
    kmac.derive_abcd(hmac, derivation_data, start_index, amount);

    return kmac;
}

/**
 * Compute single compact MAC for (x_int, x_frac).
 */
single_mac_tag MAC::single_compact_mac(Key_Generator kmac, int index, double x_int, double x_frac)
{
    // y_r = sum(a_i * x_i) + b mod p
    double sum_dvY = kmac.a_int[index] * x_int + kmac.a_frac[index] * x_frac + kmac.b[index];

    auto dvY = lldiv(sum_dvY, _enc_init_params.prime);
    double y_r = double(dvY.rem);
    double y_q = double(dvY.quot);

    auto dvYalpha = lldiv(y_q + kmac.c_alpha[index], _enc_init_params.prime);
    double y_alpha_frac = dvYalpha.rem;
    double y_alpha_int = fmod((dvYalpha.quot + kmac.d_alpha[index]), 2);

    return single_mac_tag{ y_alpha_int, y_alpha_frac, y_r };
}

/**
 * Compute optimized batched compact MAC over a vector of inputs.
 */
mac_tag_batched_optimized MAC::compact_mac_batched_optimized(Batched_Key_Generator kmac, vector<double> y_vec)
{
    double prime_square = std::pow(_enc_init_params.prime, 2);

    mac_tag_batched_optimized mac_optimized;

    for (int i = 0; i < y_vec.size(); i++)
    {
        double sum_dvY = y_vec[i];

        auto dvY = lldiv(sum_dvY, _enc_init_params.prime);
        double y_r = double(dvY.rem);
        double y_q = double(dvY.quot);

        auto alpha_beta = lldiv(y_q, _enc_init_params.prime);
        double alpha = alpha_beta.quot;
        double beta = alpha_beta.rem;

        auto dvYalpha = lldiv(alpha + kmac.c_alpha[i], _enc_init_params.prime);
        double y_alpha_frac = dvYalpha.rem;
        double y_alpha_int = fmod((dvYalpha.quot + kmac.d_alpha[i]), 2);

        auto dvYbeta = lldiv(beta + kmac.c_beta[i], _enc_init_params.prime);
        double y_beta_frac = dvYbeta.rem;
        double y_beta_int = fmod((dvYbeta.quot + kmac.d_beta[i]), 2);

        mac_optimized.mac_part1.push_back(y_alpha_frac * prime_square + y_beta_frac * _enc_init_params.prime + y_r);
        mac_optimized.mac_part2.push_back((int(y_alpha_int) << 1) | int(y_beta_int));
    }

    return mac_optimized;
}

/**
 * Compute compact MAC tag for a vector of batched keys and input vectors.
 */
compact_mac_tag MAC::compact_mac(vector<Batched_Key_Generator>& kmac_vec, vector<vector<double>>& x_int, vector<vector<double>>& x_frac, ullong input_size)
{
    int vec_size = std::min(int(input_size), _enc_init_params.max_ct_entries);
    int N_agg = ceil((input_size + 0.0) / _enc_init_params.max_ct_entries);
    int last_vec_size = (input_size % _enc_init_params.max_ct_entries == 0) ? vec_size : input_size % _enc_init_params.max_ct_entries;

    int cur_vec_size = vec_size;

    // Sum a_i * x_i + b
    vector<double> sum_dvY(vec_size, 0.0);

    for (int j = 0; j < N_agg; j++)
    {
        if (j == (N_agg - 1))
        {
            cur_vec_size = last_vec_size;
        }

        for (int i = 0; i < cur_vec_size; i++)
        {
            sum_dvY[i] += (kmac_vec[i].a_int[j] * x_int[j][i] + kmac_vec[i].a_frac[j] * x_frac[j][i]);

            if (j == 0)
            {
                sum_dvY[i] += kmac_vec[i].b[i]; // b is only added once
            }
        }
    }

    // Compute MAC components
    vector<double> y_r_vec(vec_size, 0);
    vector<double> y_alpha_int_vec(vec_size, 0);
    vector<double> y_alpha_frac_vec(vec_size, 0);
    vector<double> y_beta_int_vec(vec_size, 0);
    vector<double> y_beta_frac_vec(vec_size, 0);

    cur_vec_size = vec_size;

    for (int i = 0; i < cur_vec_size; i++)
    {
        auto dvY = lldiv(sum_dvY[i], _enc_init_params.prime);
        y_r_vec[i] = double(dvY.rem);
        double y_q = double(dvY.quot);

        auto alpha_beta = lldiv(y_q, _enc_init_params.prime);

        double alpha = alpha_beta.quot;
        double beta = alpha_beta.rem;

        auto dvYalpha = lldiv(alpha + kmac_vec[i].c_alpha[0], _enc_init_params.prime);
        y_alpha_frac_vec[i] = dvYalpha.rem;
        y_alpha_int_vec[i] = fmod((dvYalpha.quot + kmac_vec[i].d_alpha[0]), 2);

        auto dvYbeta = lldiv(beta + kmac_vec[i].c_beta[0], _enc_init_params.prime);
        y_beta_frac_vec[i] = dvYbeta.rem;
        y_beta_int_vec[i] = fmod((dvYbeta.quot + kmac_vec[i].d_beta[0]), 2);
    }

    compact_mac_tag tag;
    tag.y_r = make_shared<vector<double>>(y_r_vec);
    tag.y_alpha_int = make_shared<vector<double>>(y_alpha_int_vec);
    tag.y_alpha_frac = make_shared<vector<double>>(y_alpha_frac_vec);
    tag.y_beta_int = make_shared<vector<double>>(y_beta_int_vec);
    tag.y_beta_frac = make_shared<vector<double>>(y_beta_frac_vec);

    return tag;
}

/**
 * Verify y = a * x + b (batched, homomorphic)
 */
Ciphertext MAC::verifyHE_batched_y(const shared_ptr<seal_struct> seal_struct, Batched_Key_Generator kmac, Ciphertext ct_x_int, Ciphertext ct_x_frac, DS_performance_metrics* performanceMetrics)
{
    Ciphertext ct_result;
    Plaintext pt_a_int, pt_a_frac;

    auto start_verify = utility::timer_start();

    seal_struct->encoder_ptr->encode(kmac.a_int, _enc_init_params.scale, pt_a_int);
    seal_struct->encoder_ptr->encode(kmac.a_frac, _enc_init_params.scale, pt_a_frac);

    mult_ct_pt_inplace(seal_struct, ct_x_int, pt_a_int);
    mult_ct_pt_inplace(seal_struct, ct_x_frac, pt_a_frac);

    seal_struct->evaluator_ptr->add(ct_x_int, ct_x_frac, ct_result);

    performanceMetrics->verify += utility::timer_end(start_verify).count();

    return ct_result;
}

/**
 * Verify batched y_tag (homomorphic)
 */
Ciphertext MAC::verifyHE_batched_y_tag(const shared_ptr<seal_struct> seal_struct, int len_vec, Batched_Key_Generator kmac, Ciphertext ct_tr, Ciphertext ct_alpha_int, Ciphertext ct_beta_int, DS_performance_metrics* performanceMetrics)
{
    double p_square = _enc_init_params.prime * _enc_init_params.prime;
    double p_triple = p_square * _enc_init_params.prime;

    vector<double> signPTriple(len_vec, 1);
    vector<double> signPSquare(len_vec, 1);
    vector<double> cleartext_calc(len_vec, 0);

    auto start_verify = utility::timer_start();

    for (int i = 0; i < len_vec; i++)
    {
        if (kmac.d_alpha[i] == 1)
        {
            signPTriple[i] = -1;
            cleartext_calc[i] += p_triple - kmac.c_alpha[i] * p_square;
        }
        else
        {
            cleartext_calc[i] += -kmac.c_alpha[i] * p_square;
        }

        if (kmac.d_beta[i] == 1)
        {
            signPSquare[i] = -1;
            cleartext_calc[i] += p_square - kmac.c_beta[i] * _enc_init_params.prime;
        }
        else
        {
            cleartext_calc[i] += -kmac.c_beta[i] * _enc_init_params.prime;
        }

        cleartext_calc[i] -= kmac.b[i];
    }

    Plaintext pt_signPTriple, pt_signPSquare, cleartext_calc_pt;

    seal_struct->encoder_ptr->encode(signPTriple, _enc_init_params.scale, pt_signPTriple);
    seal_struct->encoder_ptr->encode(signPSquare, _enc_init_params.scale, pt_signPSquare);

    Ciphertext y_comp;

    mult_ct_pt_inplace(seal_struct, ct_alpha_int, pt_signPTriple);
    mult_ct_pt_inplace(seal_struct, ct_beta_int, pt_signPSquare);

    seal_struct->evaluator_ptr->add(ct_alpha_int, ct_beta_int, y_comp);

    seal_struct->evaluator_ptr->mod_switch_to_inplace(ct_tr, y_comp.parms_id());
    seal_struct->evaluator_ptr->add_inplace(y_comp, ct_tr);

    seal_struct->encoder_ptr->encode(cleartext_calc, y_comp.parms_id(), _enc_init_params.scale, cleartext_calc_pt);
    seal_struct->evaluator_ptr->add_plain_inplace(y_comp, cleartext_calc_pt);

    performanceMetrics->verify += utility::timer_end(start_verify).count();

    return y_comp;
}

/**
 * Verify compact MAC (unbatched, homomorphic)
 */
const Ciphertext& MAC::compact_unbatched_VerifyHE(const shared_ptr<seal_struct> seal_struct, Key_Generator kmac, Ciphertext& x_int, Ciphertext& x_frac, mac_tag_ct& tag_he, bool squareDiff, int len, DS_performance_metrics* performanceMetrics)
{
    double p_square = _enc_init_params.prime * _enc_init_params.prime;
    vector<double> signPSquare(len, p_square);
    vector<double> cleartext_calc(len, 0);

    auto start_verify = utility::timer_start();

    for (int i = 0; i < len; i++)
    {
        if (kmac.d_alpha[i] == 1)
        {
            signPSquare[i] = -p_square;
            cleartext_calc[i] = p_square - kmac.c_alpha[i] * _enc_init_params.prime - kmac.b[i];
        }
        else
        {
            cleartext_calc[i] = -kmac.c_alpha[i] * _enc_init_params.prime - kmac.b[i];
        }
    }

    Plaintext pt_signPSquare, cleartext_calc_pt;

    seal_struct->encoder_ptr->encode(signPSquare, _enc_init_params.scale, pt_signPSquare);

    mult_ct_pt_inplace(seal_struct, *tag_he.z_qmskd_ct, pt_signPSquare);

    Ciphertext y_comp;
    seal_struct->evaluator_ptr->mod_switch_to_inplace(*tag_he.t_r_ct, tag_he.z_qmskd_ct->parms_id());
    seal_struct->evaluator_ptr->add(*tag_he.t_r_ct, *tag_he.z_qmskd_ct, y_comp);

    seal_struct->encoder_ptr->encode(cleartext_calc, y_comp.parms_id(), _enc_init_params.scale, cleartext_calc_pt);
    seal_struct->evaluator_ptr->add_plain_inplace(y_comp, cleartext_calc_pt);

    Plaintext a_int_pt, a_frac_pt;
    seal_struct->encoder_ptr->encode(kmac.a_int, x_int.parms_id(), _enc_init_params.scale, a_int_pt);
    seal_struct->encoder_ptr->encode(kmac.a_frac, x_frac.parms_id(), _enc_init_params.scale, a_frac_pt);

    mult_ct_pt_inplace(seal_struct, x_int, a_int_pt);
    mult_ct_pt_inplace(seal_struct, x_frac, a_frac_pt);

    seal_struct->evaluator_ptr->add_inplace(x_int, x_frac);
    seal_struct->evaluator_ptr->sub(y_comp, x_int, x_int);

    performanceMetrics->verify += utility::timer_end(start_verify).count();

    // Optionally compute squared difference for tighter validation
    if (squareDiff)
    {
        auto start_square_diff = utility::timer_start();

        seal_struct->evaluator_ptr->square_inplace(x_int);
        seal_struct->evaluator_ptr->relinearize_inplace(x_int, *seal_struct->relink_ptr);
        seal_struct->evaluator_ptr->rescale_to_next_inplace(x_int);
        x_int.scale() = _enc_init_params.scale;

        performanceMetrics->square_diff += utility::timer_end(start_square_diff).count();
    }

    return x_int;
}
