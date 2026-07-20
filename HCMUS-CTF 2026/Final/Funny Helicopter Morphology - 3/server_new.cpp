#include "openfhe.h"
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include <random>
#include <ctime>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iomanip>
#include <fstream>

using namespace lbcrypto;
const uint32_t TARGET_RING_DIM = 32;
const uint32_t BATCH_SIZE = TARGET_RING_DIM;
const uint32_t AUX_RING_DIM = 8;
const uint32_t AUX_NUM_SAMPLES = 4;
const uint32_t SECRET_BIT_SIZE = 178;
const uint32_t MAIN_CIPHERTEXT_LEVELS = 3;
const uint32_t AUX_CIPHERTEXT_LEVELS = 3;
const int64_t  P_MOD = 65537;      // Plaintext modulus
const BigInteger T_MIN = BigInteger(1) << (SECRET_BIT_SIZE - 1);
const BigInteger T_MAX = BigInteger(1) << SECRET_BIT_SIZE;
const int64_t  A_COEFF_BOUND = 1;
const int64_t  B_COEFF_BOUND = 64;
const double   A_ERROR_SIGMA = 2.0;
const double   B_ERROR_SIGMA = 64.0;
const int      PORT = 1337;

CryptoContext<DCRTPoly> cc;
DCRTPoly T; 
DCRTPoly S;
BigInteger aux_modulus;
BigInteger aux_q0;
std::vector<BigInteger> S_otp;
std::vector<DCRTPoly> B_samples;
std::vector<DCRTPoly> S_samples;
std::vector<DCRTPoly> K_samples;
std::string encrypted_flag_1;
std::mt19937_64 rng;

size_t GetRingDim() {
    return cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
}

uint64_t MaskBits(uint32_t bits) {
    if (bits == 0) return 0;
    if (bits >= 64) return 0xffffffffffffffffULL;
    return (1ULL << bits) - 1;
}

BigInteger SampleBelow(const BigInteger& bound) {
    std::uniform_int_distribution<uint64_t> dist(0, 0xffffffffffffffffULL);
    uint32_t bitlen = bound.GetMSB();
    BigInteger candidate;
    do {
        candidate = BigInteger(0);
        for (uint32_t shift = 0; shift < bitlen; shift += 64) {
            uint32_t chunkBits = std::min<uint32_t>(64, bitlen - shift);
            candidate += BigInteger(dist(rng) & MaskBits(chunkBits)) << shift;
        }
    } while (candidate >= bound);
    return candidate;
}

// --- Helper: Generate T ---
template <typename ParamsPtr>
DCRTPoly GenLargeSecretPoly(const ParamsPtr& params, size_t ring_dim) {
    std::vector<BigInteger> coeffs(ring_dim);
    const BigInteger range = T_MAX - T_MIN;
    for (auto& coeff : coeffs) {
        coeff = T_MIN + SampleBelow(range);
    }
    std::sort(coeffs.begin(), coeffs.end());

    DCRTPoly poly(params, COEFFICIENT, true);
    for (size_t i = 0; i < poly.GetNumOfElements(); i++) {
        auto tower_params = params->GetParams()[i];
        DCRTPoly::PolyType v(tower_params, COEFFICIENT, true);
        auto modulus = tower_params->GetModulus().ConvertToInt();
        std::vector<int64_t> reduced_coeffs(ring_dim);
        for (size_t j = 0; j < ring_dim; j++) {
            reduced_coeffs[j] = (coeffs[j] % modulus).ConvertToInt();
        }
        v = reduced_coeffs;
        poly.SetElementAtIndex(i, v);
    }
    poly.SetFormat(EVALUATION);
    return poly;
}

template <typename ParamsPtr>
DCRTPoly GenSmallUniformPoly(const ParamsPtr& params, size_t ring_dim, int64_t bound) {
    std::uniform_int_distribution<int64_t> dist(-bound, bound);
    std::vector<int64_t> coeffs(ring_dim);
    for (auto& coeff : coeffs) {
        coeff = dist(rng);
    }

    DCRTPoly poly(params, COEFFICIENT, true);
    poly = coeffs;
    poly.SetFormat(EVALUATION);
    return poly;
}

std::vector<BigInteger> GetPolyCoefficients(DCRTPoly poly) {
    poly.SetFormat(COEFFICIENT);
    Poly poly_reconstructed = poly.CRTInterpolate();
    auto values = poly_reconstructed.GetValues();

    std::vector<BigInteger> coeffs(values.GetLength());
    for (size_t i = 0; i < values.GetLength(); i++) {
        coeffs[i] = values[i];
    }
    return coeffs;
}

std::vector<BigInteger> GetPolyCoefficientsCenteredForMod(DCRTPoly poly, const BigInteger& targetModulus) {
    poly.SetFormat(COEFFICIENT);
    Poly poly_reconstructed = poly.CRTInterpolate();
    auto values = poly_reconstructed.GetValues();
    auto sourceModulus = poly_reconstructed.GetModulus();
    auto sourceHalf = sourceModulus / 2;

    std::vector<BigInteger> coeffs(values.GetLength());
    for (size_t i = 0; i < values.GetLength(); i++) {
        auto val = values[i];
        if (val > sourceHalf) {
            auto magnitude = (sourceModulus - val) % targetModulus;
            coeffs[i] = magnitude == BigInteger(0) ? BigInteger(0) : targetModulus - magnitude;
        } else {
            coeffs[i] = val % targetModulus;
        }
    }
    return coeffs;
}

BigInteger SignedMagnitudeMod(const BigInteger& value, const BigInteger& modulus) {
    BigInteger reduced = value % modulus;
    BigInteger complement = reduced == BigInteger(0) ? BigInteger(0) : modulus - reduced;
    return reduced < complement ? reduced : complement;
}

std::string VectorToString(const std::vector<BigInteger>& values) {
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < values.size(); i++) {
        ss << values[i].ToString() << (i == values.size() - 1 ? "" : ", ");
    }
    ss << "]";
    return ss.str();
}

std::vector<BigInteger> GetPolyCoefficientsSigned(DCRTPoly poly) {
    poly.SetFormat(COEFFICIENT);
    Poly poly_reconstructed = poly.CRTInterpolate();
    auto values = poly_reconstructed.GetValues();
    auto q = poly_reconstructed.GetModulus();
    auto qHalf = q / 2;

    std::vector<BigInteger> coeffs(values.GetLength());
    for (size_t i = 0; i < values.GetLength(); i++) {
        auto val = values[i];
        if (val > qHalf) {
            coeffs[i] = (BigInteger(1) << 128) - (q - val);
        } else {
            coeffs[i] = val;
        }
    }
    return coeffs;
}

std::string HexEncode(const std::string& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char ch : data) {
        oss << std::setw(2) << static_cast<int>(ch);
    }
    return oss.str();
}

std::string GenerateRandomHex(size_t byte_len) {
    static constexpr char HEX_DIGITS[] = "0123456789abcdef";
    std::uniform_int_distribution<int> dist(0, 255);

    std::string out;
    out.reserve(byte_len * 2);
    for (size_t i = 0; i < byte_len; i++) {
        unsigned char byte = static_cast<unsigned char>(dist(rng));
        out.push_back(HEX_DIGITS[byte >> 4]);
        out.push_back(HEX_DIGITS[byte & 0x0f]);
    }
    return out;
}

std::string ReadFlag(const std::string& path) {
    std::ifstream file(path);
    std::string flag;
    std::getline(file, flag);
    while (!flag.empty() && (flag.back() == '\n' || flag.back() == '\r')) {
        flag.pop_back();
    }
    if (flag.rfind("HCMUS-CTF{", 0) == 0 && flag.back() == '}') {
        return flag.substr(10, flag.length() - 11);
    }
    return flag;
}

void InitEncryptedFlag() {
    const std::vector<BigInteger> t_coeffs = GetPolyCoefficientsSigned(T);
    std::cout << "t_coeffs [";
    for (size_t i = 0; i < t_coeffs.size(); i++) {
        std::cout << t_coeffs[i].ToString() << (i == t_coeffs.size() - 1 ? "" : ", ");
    }
    std::cout << "]" << std::endl;

    std::vector<unsigned char> key_bytes;
    key_bytes.reserve(t_coeffs.size() * 16);
    for (const auto& coeff : t_coeffs) {
        for (int j = 0; j < 16; j++) {
            key_bytes.push_back(static_cast<unsigned char>(((coeff >> (j * 8)) % 256).ConvertToInt()));
        }
    }
    // TODO DEBUG
    // std::cout << "key_bytes [";
    // for (size_t i = 0; i < key_bytes.size(); i++) {
    //     std::cout << (int)key_bytes[i] << (i == key_bytes.size() - 1 ? "" : ", ");
    // }
    // std::cout << "]" << std::endl;

    auto encrypt_body = [&](const std::string& body) {
        std::string flag_body = body;
        constexpr size_t target_len = 64;

        if (flag_body.length() < target_len) {
            size_t needed = target_len - flag_body.length();
            std::string padding = GenerateRandomHex((needed + 1) / 2);
            flag_body += padding.substr(0, needed);
        } else if (flag_body.length() > target_len) {
            flag_body = flag_body.substr(0, target_len);
        }

        std::string masked_body = flag_body;
        for (size_t i = 0; i < key_bytes.size(); i++) {
            unsigned char mask = key_bytes[i];
            masked_body[i % flag_body.size()] ^= mask;
        }
        return HexEncode(masked_body);
    };

    encrypted_flag_1 = encrypt_body(ReadFlag("deploy/flag.txt"));
}

// --- Helper: Serialize Polynomial to String ---
std::string PolyToString(DCRTPoly p) {
    p.SetFormat(COEFFICIENT);
    // Use CRT interpolation to get the coefficients mod q
    Poly p_reconstructed = p.CRTInterpolate();
    auto values = p_reconstructed.GetValues();
    
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < values.GetLength(); i++) {
        ss << values[i].ToString() << (i == (values.GetLength() - 1) ? "" : ", ");
    }
    ss << "]";
    return ss.str();
}

std::string PolyToStringModQ(DCRTPoly p, const BigInteger& q) {
    auto coeffs = GetPolyCoefficientsCenteredForMod(p, q);
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < coeffs.size(); i++) {
        ss << coeffs[i].ToString() << (i == (coeffs.size() - 1) ? "" : ", ");
    }
    ss << "]";
    return ss.str();
}

std::string PolyToSignedString(DCRTPoly p) {
    p.SetFormat(COEFFICIENT);
    Poly p_reconstructed = p.CRTInterpolate();
    auto values = p_reconstructed.GetValues();
    auto q = p_reconstructed.GetModulus();
    auto qHalf = q / 2;

    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < values.GetLength(); i++) {
        auto val = values[i];
        if (val > qHalf) {
            ss << "-" << (q - val).ToString();
        } else {
            ss << val.ToString();
        }
        ss << (i == (values.GetLength() - 1) ? "" : ", ");
    }
    ss << "]";
    return ss.str();
}



void init_challenge() {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(P_MOD);
    parameters.SetRingDim(TARGET_RING_DIM);
    parameters.SetBatchSize(BATCH_SIZE);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetMultiplicativeDepth(MAIN_CIPHERTEXT_LEVELS);
    cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto params = cc->GetCryptoParameters()->GetElementParams();
    DCRTPoly::DggType bErrorDgg(B_ERROR_SIGMA);

    CCParams<CryptoContextBFVRNS> auxParameters;
    auxParameters.SetPlaintextModulus(P_MOD);
    auxParameters.SetRingDim(AUX_RING_DIM);
    auxParameters.SetBatchSize(AUX_RING_DIM);
    auxParameters.SetSecurityLevel(HEStd_NotSet);
    auxParameters.SetMultiplicativeDepth(AUX_CIPHERTEXT_LEVELS );
    CryptoContext<DCRTPoly> aux_cc = GenCryptoContext(auxParameters);
    auto auxParams = aux_cc->GetCryptoParameters()->GetElementParams();
    aux_modulus = auxParams->GetModulus();
    aux_q0 = auxParams->GetParams()[0]->GetModulus();

    T = GenLargeSecretPoly(auxParams, AUX_RING_DIM);
    InitEncryptedFlag();

    B_samples.clear();
    K_samples.clear();
    S_samples.clear();
    B_samples.reserve(AUX_NUM_SAMPLES);
    K_samples.reserve(AUX_NUM_SAMPLES);
    S_samples.reserve(AUX_NUM_SAMPLES);
    for (uint32_t i = 0; i < AUX_NUM_SAMPLES; i++) {
        DCRTPoly B_i = GenSmallUniformPoly(auxParams, AUX_RING_DIM, B_COEFF_BOUND);
        DCRTPoly K_i(bErrorDgg, auxParams, EVALUATION);
        B_samples.push_back(B_i);
        K_samples.push_back(K_i);
        S_samples.push_back(B_i * T + K_i);
    }

    std::vector<BigInteger> s_combined;
    std::vector<BigInteger> s_aux;
    for (auto& s_samp : S_samples) {
        auto coeffs = GetPolyCoefficients(s_samp);
        s_aux.reserve(s_aux.size() + coeffs.size());
        s_combined.reserve(s_combined.size() + coeffs.size());
        for (auto& coeff : coeffs) {
            s_aux.push_back(coeff % aux_modulus);
            s_combined.push_back(BigInteger(0));
        }
    }
    params = cc->GetCryptoParameters()->GetElementParams();
    const BigInteger mainModulus = params->GetModulus();
    const BigInteger otpBound = BigInteger(1) << (aux_modulus.GetMSB() - 2);
    S_otp.clear();
    S_otp.reserve(s_combined.size());
    for (size_t i = 0; i < s_combined.size(); i++) {
        BigInteger masked = SampleBelow(otpBound);
        BigInteger otp = (masked + mainModulus - (s_aux[i] % mainModulus)) % mainModulus;
        S_otp.push_back(otp);
        s_combined[i] = masked;
    }

    Poly s_poly(params, COEFFICIENT, true);
    for (size_t i = 0; i < s_combined.size(); i++) {
        s_poly[i] = s_combined[i];
    }
    S = DCRTPoly(params, COEFFICIENT, true);
    S = s_poly;
    S.SetFormat(EVALUATION);

    // TODO DEBUG
    // std::vector<BigInteger> k_combined;
    // for (auto& k_samp : K_samples) {
    //     auto coeffs = GetPolyCoefficients(k_samp);
    //     k_combined.reserve(k_combined.size() + coeffs.size());
    //     for (auto& coeff : coeffs) {
    //         k_combined.push_back(coeff % aux_modulus);
    //     }
    // }

    // std::cout << "S " << PolyToString(S) << std::endl;
    // std::cout << "K " << VectorToString(k_combined) << std::endl;
    // std::cout << "T " << PolyToString(T) << std::endl;
}

void handle_client(int client_fd) {
    std::string banner = "=== Funny Helicopter Morphology - version Beef Feast Victory!! ===\n";
    send(client_fd, banner.c_str(), banner.length(), 0);

    char buffer[4096];
    while (true) {
        memset(buffer, 0, 4096);
        int bytes = recv(client_fd, buffer, 4096, 0);
        if (bytes <= 0) break;

        std::string cmd(buffer, bytes);
        std::stringstream ss(cmd);
        std::string action;
        ss >> action;

        if (action == "PARAMS") {
            auto params = cc->GetCryptoParameters()->GetElementParams();
            std::string res = "n: " + std::to_string(GetRingDim()) + "\n" +
                             "q: " + params->GetModulus().ToString() + "\n" +
                             "q0: " + params->GetParams()[0]->GetModulus().ToString() + "\n" +
                             "Encrypted flag: " + encrypted_flag_1 + "\n" +
                             "OTP: " + VectorToString(S_otp) + "\n";
            send(client_fd, res.c_str(), res.length(), 0);
        }
        // else if (action == "EVALSUM") {
        //     if (used_params) {
        //         continue;
        //     }
        //     std::stringstream res;
        //     res << "q_aux: " << aux_modulus.ToString() << "\n";
        //     res << "q_aux_0: " << aux_q0.ToString() << "\n";
        //     for (size_t i = 0; i < B_samples.size(); i++) {
        //         res << "B" << i << ": " << PolyToSignedString(B_samples[i]) << "\n";
        //         res << "S" << i << ": " << PolyToSignedString(S_samples[i]) << "\n";
        //     }
        //     res << "OTP: " << VectorToString(S_otp) << "\n";
           
        //     std::string out = res.str();
        //     send(client_fd, out.c_str(), out.length(), 0);
        // }
        else if (action == "CHALLENGE") {
            int num_samples;
            if (!(ss >> num_samples)) {
                std::string err = "ERROR: Provide number of samples.\n";
                send(client_fd, err.c_str(), err.length(), 0);
                continue;
            }
            if (num_samples < 1 || num_samples > 50) {
                std::string err = "ERROR: Too many samples.\n";
                send(client_fd, err.c_str(), err.length(), 0);
                continue;
            }

            std::vector<int64_t> v_vals;
            int64_t val;
            while (ss >> val) v_vals.push_back(val);
            
            if (v_vals.empty()) {
                std::string err = "ERROR: Provide at least one message value.\n";
                send(client_fd, err.c_str(), err.length(), 0);
                continue;
            }

            try {
                std::stringstream ss_res;
                Plaintext pt = cc->MakePackedPlaintext(v_vals);
                
                const auto& elementParams = cc->GetCryptoParameters()->GetElementParams();

                pt->Encode();
                DCRTPoly m_poly = pt->GetElement<DCRTPoly>();
                m_poly.SetFormat(EVALUATION);

                DCRTPoly::DggType aErrorDgg(A_ERROR_SIGMA);
                BigInteger r(std::uniform_int_distribution<uint64_t>(2, 1ULL << 20)(rng));
                ss_res << "r: " << r << "\n";
                for (uint32_t i = 0; i < (uint32_t)num_samples; i++) {
                    DCRTPoly a = GenSmallUniformPoly(elementParams, GetRingDim(), A_COEFF_BOUND);
                    DCRTPoly e(aErrorDgg, elementParams, EVALUATION);
                    
                    // TODO DEBUG
                    // std::cout << "e[" << i << "] " << PolyToString(e) << std::endl;
                    
                    DCRTPoly c0 = a * S + e * r + m_poly;
                    
                    a.SetFormat(COEFFICIENT);
                    c0.SetFormat(COEFFICIENT);
                    
                    ss_res << "SAMPLE " << i << "\n";
                    ss_res << "C1: " << PolyToString(a) << "\n";
                    ss_res << "C0: " << PolyToString(c0) << "\n";
                }

                // free hints!!
                // std::vector<BigInteger> e_coeffs;
                // for (auto& k_samp : K_samples) {
                //     auto coeffs = GetPolyCoefficientsSigned(k_samp);
                //     e_coeffs.insert(e_coeffs.end(), coeffs.begin(), coeffs.end());
                // }
                // for (size_t i = 0; i < std::min<size_t>(2, e_coeffs.size()); i++) {
                //     ss_res << "E[" << i << "]: " << e_coeffs[i].ToString() << "\n";
                // }

                std::string res = ss_res.str();
                send(client_fd, res.c_str(), res.length(), 0);
            } catch (const std::exception& e) {
                std::string err = "ERROR: " + std::string(e.what()) + "\n";
                send(client_fd, err.c_str(), err.length(), 0);
            }

            break;
        }
        else if (action == "EXIT") break;
    }
    close(client_fd);
}

int main() {
    rng.seed(std::random_device{}());

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) return 1;
    listen(server_fd, 5);
    std::cout << "Server listening on port " << PORT << std::endl;  

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd >= 0) {
            rng.seed(std::random_device{}());
            init_challenge();
            handle_client(client_fd);
        }
    }
    return 0;
}
