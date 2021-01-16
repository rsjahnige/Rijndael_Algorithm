# Advanced Encryption Standard
Out of respect for the designers, this repository is named after the original algorithm proposed by Joan Daemen and Vincent Rijmen. However, it is important to note that the code contained herein conforms to the **Advanced Encryption Standard (AES)** defined in FIPS PUB 197.

Rijndael supports additional block sizes and key sizes that are not specified for AES. Theoretically, this code should support the additional parameters defined for the Rijndael algorithm although this behavior has not been tested and would require some minor tweaking of the code. Please see [Implementation Notes](#Rijndael) for a further explanation. 

## How to use
Available functions and data structures are defined within the **aes.h** header file.\
Encrypting a data block:
```
int keySize = 128, 192, 256; // Choose one
struct AES params;
struct word* w;
unsigned char* key;
unsigned char in[4*Nb] = {}; // Initialize input data block 
unsigned char out[4*Nb];

if (__init__(&params, keySize) < 0) 
  exit(EXIT_FAILURE);

w = malloc(sizeof(struct word)*Nb*(params.Nr+1));
key = malloc(4*params.Nk);

KeyExpansion(params, key, w);
Cipher(params, in, out, w);

free(key);
free(w); 

return out; // Ciphertext stored in out[] array
```
The same procedure can be used to decrypt a data block by replacing the Cipher() function call with InvCipher(). Please take a look at the **htest.c** file for a full example.

## Implementation Notes
This section will discuss parts of the code that I believe need improvment as well as general comments I have about the implementation.

### Rijndael Algorithm

### Eucildean Algorithm

### Sanitizing Input

## References
