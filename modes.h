#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>

#include "aes.h"

#define CBC 0

ssize_t cbc_enc(const AES params, word* w, unsigned char iv[4*Nb], unsigned char block[1024], ssize_t blockSize);
ssize_t cbc_dec(const AES params, word* w, unsigned char iv[4*Nb], unsigned char block[1024], ssize_t blockSize);

int encrypt_file(const char* fileName, const char* pw, const int mode, const int keySize);
int decrypt_file(const char* fileName, const char* pw);


