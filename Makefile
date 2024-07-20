all:
	@cc -Wall -Wextra -o mgit src/main.c -lz -lssl -lcrypto