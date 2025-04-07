#include "TOTP.h"

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        printf("\nThis program is used to verify the one-time dynamic password (TOTP), the algorithm adopts SHA1 to return 0 for success, and -1 for failure.\n");
        printf("Using:%s otp_sn otp_password\n", argv[0]);
        printf("example:%s otp_sn 123456\n\n", argv[0]);
        return -1;
    }
	std::string otp_sn;
	std::string otp;
	otp_sn=argv[1];
	otp=argv[2];
    if (0 == TOTP::ET_CheckPwdz201_ext(otp_sn,otp))
    {
        printf("\nVerified successfully!\n\n");
        return 0;
    }

    printf("\nVerified failed!\n\n");

    return 0;
}

