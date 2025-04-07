CC=g++
FALGS=-std=c++14 -W -O2

all:totp_chk totp_gen

totp_chk:main.cxx TOTP.cxx
	$(CC) $(FALGS) -o totp_chk main.cxx TOTP.cxx -lssl -lcrypto -ldl -lpthread

totp_gen:main_gen.cxx TOTP.cxx
	$(CC) $(FALGS) -o totp_gen main_gen.cxx TOTP.cxx -lssl -lcrypto -ldl -lpthread
	
clean:
	rm -f totp_chk
	rm -f totp_gen

