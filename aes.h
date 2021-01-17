#ifndef AES_H
#define AES_H

#define Nb 4 // Block Size; Same for all key sizes in AES

struct AES {
  int Nk, Nr;
};

struct word {
  unsigned char wd[4];
}; 

int __init__(struct AES* self, int keySize); // Constructor

int KeyExpansion(struct AES self, unsigned char* key, struct word* w); 
int Cipher(struct AES self, unsigned char in[4*Nb], unsigned char out[4*Nb], struct word* w);
int InvCipher(struct AES self, unsigned char in[4*Nb], unsigned char out[4*Nb], struct word* w);

#endif
