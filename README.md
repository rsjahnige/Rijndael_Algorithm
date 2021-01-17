# Advanced Encryption Standard
To show my admiration, this repository is named after the original algorithm proposed by Joan Daemen and Vincent Rijmen. However, the code contained herein conforms to the **Advanced Encryption Standard (AES)** defined in FIPS PUB 197 [].

Rijndael supports additional block sizes and key sizes that are not specified for AES. Theoretically, this code should support the additional parameters defined for the Rijndael algorithm although this behavior has not been tested and would require some minor tweaking of the code. Please see [Implementation Notes](#Rijndael-Algorithm) for a further explanation. 

## How to use
Available functions and data structures are defined within the **aes.h** header file.\
The following steps can be used to encrypt a 128 bit data block:
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
The same procedure can be used to decrypt a 128 bit data block by replacing the Cipher() function call with InvCipher(). For a full example, refer to the **htest.c** file.

## Implementation Notes
This section will discuss parts of the code that I believe need improvment as well as general comments I have about the implementation.

#### Rijndael Algorithm
To implement the Rijndael Algotithm, several updates will need to be made to the \_\_init()\_\_ function. Since AES uses a fixed 128 bit input block size for all key sizes, \'Nb\' has been defined as a marco. This is effective for the AES implementation although it cannot be used for the Rijndael algorithm. To support the varying block sizes of the Rijndael algorithm would required \'Nb\' to be initialized along with the other parameters in the \_\_init()\_\_ function. Furthermore, several auxilary functions use \'Nb\' for iteration so this value would need to be included in the paramater list for those functions since it is no longer globally available.  To my knowledge, all other code in **aes.c** can remain the same.

#### Eucildean Algorithm
The Eucildean Algorithm is used to derive the multiplicative inverse with the finite field GF(2<sup>8</sup>).


#### Sanitizing Input

## References
