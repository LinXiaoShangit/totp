#ifndef __TOTP_H
#define __TOTP_H

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <ctime>
#include <iomanip>
#include <algorithm>

#define PUBLIC_KEY "AE548C9CDF39F43B9ED7358852F8CC6BK3D92B2B"//与客户端约定公钥

#define CC_SHA1_DIGEST_LENGTH   20
#define CC_SHA256_DIGEST_LENGTH 32
#define CC_SHA512_DIGEST_LENGTH 64

class TOTP
{
public:
    enum class Hash {HMACSHA1, HMACSHA256, HMACSHA512};

private:
    static const int DIGITS_POWER[];
#ifdef __APPLE__
    static void hmac_sha(Hash hash, const void *key, size_t key_len, const void *data, size_t data_len, void *mac_out);
#else
    static unsigned char * hmac_sha(Hash hash, const void *key, int key_len, const unsigned char *d, int n, unsigned char *md, unsigned int *md_len);
#endif
    static std::vector<unsigned char> hexStr2Bytes(std::string &hex);

public:
    static std::string generateTOTP(std::string &key, std::string &time, std::string &returnDigits);
    static std::string generateTOTP256(std::string &key, std::string &time, std::string &returnDigits);
    static std::string generateTOTP512(std::string &key, std::string &time, std::string &returnDigits);
    static std::string generateTOTP(std::string &key, std::string &time, std::string &returnDigits, Hash hash);
    static std::string toHexString(long T);
    static int ET_CheckPwdz201(const std::string& otp, int otplen=6, long X=60, time_t T0=0, long t=0);
	
	static std::string generateTOTP_ext(std::string &otp_sn,std::string &time, std::string &returnDigits, Hash hash);
	static int ET_CheckPwdz201_ext(std::string& otp_sn,std::string& otp, int otplen=6, long X=60, time_t T0=0, long t=0);
};

#endif

