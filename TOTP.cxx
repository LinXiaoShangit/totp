#ifdef __APPLE__
    #include <CommonCrypto/CommonHMAC.h>
#else
    #include <openssl/evp.h>
    #include <openssl/hmac.h>
#endif

#include <vector>

#include "TOTP.h"

const int TOTP::DIGITS_POWER[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};


std::vector<unsigned char> TOTP::hexStr2Bytes(std::string &hex)
{
    std::stringstream ss;
    unsigned int buffer;
    unsigned int offset = 0;

    std::vector<unsigned char> bytes;

    while (offset < hex.length())
    {
        ss.clear();
        ss << std::hex << hex.substr(offset, 2);
        ss >> buffer;

        bytes.emplace_back(static_cast<unsigned char>(buffer));
        offset += 2;
    }

    return bytes;
}

#ifdef __APPLE__
void TOTP::hmac_sha(Hash hash, const void *key, size_t key_len, const void *data, size_t data_len, void *mac_out)
{
    CCHmacAlgorithm algorithm;

    switch (hash) {
        default:
        case Hash::HMACSHA1: algorithm = kCCHmacAlgSHA1; break;
                case Hash::HMACSHA256: algorithm = kCCHmacAlgSHA256; break;
        case Hash::HMACSHA512: algorithm = kCCHmacAlgSHA512; break;
    }

    CCHmac(algorithm, key, key_len, data, data_len, mac_out);
}
#else
unsigned char * TOTP::hmac_sha(Hash hash, const void *key, int key_len, const unsigned char *d, int n, unsigned char *md, unsigned int *md_len)
{
    const EVP_MD *evp_md;

    switch(hash)
    {
        default:
        case Hash::HMACSHA1: evp_md = EVP_sha1(); break;
        case Hash::HMACSHA256: evp_md = EVP_sha256(); break;
        case Hash::HMACSHA512: evp_md = EVP_sha512(); break;
    }

    return HMAC(evp_md, key, key_len, d, n, md, md_len);
}
#endif

std::string TOTP::generateTOTP(std::string &key, std::string &time, std::string &returnDigits)
{
    return generateTOTP(key, time, returnDigits, Hash::HMACSHA1);
}

std::string TOTP::generateTOTP256(std::string &key, std::string &time, std::string &returnDigits)
{
    return generateTOTP(key, time, returnDigits, Hash::HMACSHA256);
}

std::string TOTP::generateTOTP512(std::string &key, std::string &time, std::string &returnDigits)
{
    return generateTOTP(key, time, returnDigits, Hash::HMACSHA512);
}

std::string TOTP::generateTOTP(std::string &key, std::string &time, std::string &returnDigits, Hash hash)
{
    unsigned int codeDigits = atoi(returnDigits.c_str());
    std::string result;
    
    while (time.length() < 16)
    {
        time = "0" + time;
    }

    std::vector<unsigned char> msg = hexStr2Bytes(time);
    std::vector<unsigned char> k = hexStr2Bytes(key);

    unsigned int HASH_LENGTH;
    switch (hash) {
        default:
        case Hash::HMACSHA1: HASH_LENGTH = CC_SHA1_DIGEST_LENGTH; break;
        case Hash::HMACSHA256: HASH_LENGTH = CC_SHA256_DIGEST_LENGTH; break;
        case Hash::HMACSHA512: HASH_LENGTH = CC_SHA512_DIGEST_LENGTH; break;
    }

    unsigned char hmac[HASH_LENGTH];
    unsigned int hmac_length;
#ifdef __APPLE__
    hmac_sha(hash, k.data(), k.size(), msg.data(), msg.size(), hmac);

    hmac_length = HASH_LENGTH;
#else
    hmac_sha(hash, k.data(), k.size(), msg.data(), msg.size(), hmac, &hmac_length);
#endif

    int offset = hmac[hmac_length - 1] & 0xf;
    int binary =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);

    int otp = binary % DIGITS_POWER[codeDigits];
    result = std::to_string(otp);

    while (result.length() < codeDigits)
        result = "0" + result;

    return result;
}

std::string TOTP::toHexString(long T)
{
    std::string hex;
    std::ostringstream oss;

    oss << std::hex << T;
    hex = oss.str();
    std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);

    return hex;
}

int TOTP::ET_CheckPwdz201(const std::string& otp, int otplen, long X, time_t T0, long t)
{
    std::string steps = "";
    std::string return_digits = std::to_string(otplen);

    time_t ltime = t;

    if (t == 0)
    {
        ltime = time(NULL);
    }

    long T;
    T = (ltime - T0) / X;
    //std::cout << std::endl << "T==" << T << "  ltime==" << ltime << std::endl;
    steps = toHexString(T);

    //std::cout << std::put_time(std::gmtime(&ltime), "%F %X") << "\n";
    //std::cout << TOTP::generateTOTP(PUBLIC_KEY, steps, return_digits, TOTP::Hash::HMACSHA512) << "==SHA512==" << "\n";
    //std::cout << TOTP::generateTOTP(PUBLIC_KEY, steps, return_digits, TOTP::Hash::HMACSHA256) << "==SHA256==" << "\n";
    std::string publicKey = PUBLIC_KEY;
    std::string passwd = TOTP::generateTOTP(publicKey, steps, return_digits, TOTP::Hash::HMACSHA1);
    //std::cout << "SHA1==" << passwd << "\n";
    /* 第一次验证, 预期成功 */
    if (passwd == otp)
    {
        return 0;
    }

    /* 若在前后两秒的范围内可以认为密码正确 */
    time_t i = ltime - 2;
    while (i < ltime + 3)
    {
        //std::cout << "i" << i << "\n";
        if (i == ltime)
        {
            ++i;
            continue;
        }

        T = (i - T0) / X;
        steps = toHexString(T);
        passwd = TOTP::generateTOTP(publicKey, steps, return_digits, TOTP::Hash::HMACSHA1);

        if (passwd == otp)
        {
            //std::cout << "已经出现" << i-ltime << "秒的偏差, 请校准\n";
            return 0;
        }

        ++i;
    }

    /* 增加前后一个延时窗口 */
    //std::cout << "T" << T << "\n";
    //steps = toHexString(T-1);
    //passwd = TOTP::generateTOTP(publicKey, steps, return_digits, TOTP::Hash::HMACSHA1);
    //if (passwd == otp)
    //{
    //    return 0;
    //}
    //steps = toHexString(T+1);
    //passwd = TOTP::generateTOTP(publicKey, steps, return_digits, TOTP::Hash::HMACSHA1);
    //if (passwd == otp)
    //{
    //    return 0;
    //}

    return -1;
}


std::string TOTP::generateTOTP_ext(std::string &otp_sn,std::string &time, std::string &returnDigits, Hash hash)
{
    std::string publicKey = PUBLIC_KEY;
	publicKey.append(otp_sn);
    std::string passwd = TOTP::generateTOTP(publicKey,time, returnDigits,  hash);
    //std::cout << "SHA1==" << passwd << "\n";
	return passwd;
}

int TOTP::ET_CheckPwdz201_ext(std::string& otp_sn,std::string& otp,int otplen, long X, time_t T0, long t)
{
    std::string steps = "";
    std::string return_digits = std::to_string(otplen);

    time_t ltime = t;

    if (t == 0)
    {
        ltime = time(NULL);
    }

    long T;

    std::string passwd;
    /* 若在前后25秒的范围内可以认为密码正确 */
    time_t i = ltime - 25;
    while (i < ltime + 25)
    {
        T = (i - T0) / X;
        steps = toHexString(T);
        passwd = TOTP::generateTOTP_ext(otp_sn, steps, return_digits, TOTP::Hash::HMACSHA1);

        if (passwd == otp)
        {
            //std::cout << "已经出现" << i-ltime << "秒的偏差, 请校准\n";
            return 0;
        }

        i++;
    }
 

    return -1;
}
