#include <stdio.h>
#include <stdlib.h>
#include "aes.h"

//Key used to test key expansion funtionality
//unsigned char key[4*Nk] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

// Key used to test ciphering funtionality
// unsigned char key[4*8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

int main(int argc, char* argv[]) {

  struct AES test;
  unsigned char* key;
  struct word* w;
  unsigned char out[4*Nb];
  unsigned char in[4*Nb] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  
  if (__init__(&test, atoi(argv[1])) < 0) exit(EXIT_FAILURE);

  w = malloc(sizeof(struct word)*Nb*(test.Nr+1));
  key = malloc(4*test.Nk);
  for (int i=0; i < 4*test.Nk; i++) key[i] = (unsigned char)i; // initialize key
  
  // Print input plaintext
  printf("Input: ");
  for (int i=0; i < 4*Nb; i++) {
    printf("%02x", in[i]);
  }
  printf("\n");
  
  KeyExpansion(test, key, w);
  Cipher(test, in, out, w);

  // Print encrypted plaintext
  printf("Cipher: ");
  for (int i=0; i < 4*Nb; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");
  
  InvCipher(test, out, in, w);

  // Print decrypted ciphertext
  printf("Plaintext: ");
  for (int i=0; i < 4*Nb; i++) {
    printf("%02x", in[i]);
  }
  printf("\n");


  free(w);
  free(key);
  return 0;
}
