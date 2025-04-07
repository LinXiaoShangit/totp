#include "TOTP.h"

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("\nThis program is used to verify the one-time dynamic password (TOTP), the algorithm adopts SHA1 to return 0 for success, and -1 for failure.\n");
        printf("Using:%s otp_sn\n", argv[0]);
        return -1;
    }	
    
	std::string otp_sn =argv[1];

    int otplen=6; long X=60; time_t T0=0; long t=0;

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
    steps = TOTP::toHexString(T);
	
	std::string passwd =TOTP::generateTOTP_ext(otp_sn, steps, return_digits, TOTP::Hash::HMACSHA1);
    std::cout << "SHA1==" << passwd << "\n";
	
    return 0;
}

