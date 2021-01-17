# Advanced Encryption Standard
To show my admiration, this repository is named after the original algorithm proposed by Joan Daemen and Vincent Rijmen. However, the code contained herein conforms to the **Advanced Encryption Standard (AES)** defined in FIPS PUB 197 \[1\].

The code available in this repository was written to satisfy my own curiosity. **I am not a cybersecurity profesional and this code has only been tested with the example vectors provided in Appendix C of \[1\].**

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
Rijndael \[2,3\] supports additional block sizes and key sizes that are not specified for AES. Theoretically, this code should support the additional parameters defined for the Rijndael algorithm although this behavior has not been tested. To implement the Rijndael Algotithm, several updates will need to be made to the \_\_init\_\_() function. Since AES uses a fixed 128 bit input block size for all key sizes, \'Nb\' has been defined as a marco. This is effective for the AES implementation although it cannot be used for the Rijndael algorithm. To support the varying block sizes of the Rijndael algorithm, it would required \'Nb\' to be initialized along with the other parameters in the \_\_init\_\_() function. Furthermore, several auxilary functions use \'Nb\' for iteration so this value would need to be included in the paramater list for those functions since it will no longer be globally available. To my knowledge, all other code in **aes.c** file can remain the same.

#### Eucildean Algorithm
To prevent possible cache or timing side-channel attacks associated with accessing a predefined S-Box array, the Eucildean Algorithm is used to derive the multiplicative inverse within the finite field GF(2<sup>8</sup>). The current state of the EuclidAlgo() function is not pretty but it is effective. The first column of the eucild_matrix is currently unused and can easily be removed. I would also like to find an implemention that does not invole casting between \'unsigned short\' and \'unsigned char\`.

#### Sanitizing Input
The only function that currently sanitizes the input is the \_\_init\_\_() function. All other functions (i.e., KeyExpansion(), Cipher(), and InvCipher()) permit the input of arbitrarily sized arrays which could cause the program to crash, or worse, it could lead to buffer overflow attacks. For now, just provide the right length input for all arrays and there shouldn't be any problems.

## References
\[1\] FIPS PUB 197, Advanced Encryption Standard (AES), National Institute of Standards and Technology, U.S. Department of Commerce, November 2001. http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf \
\[2\] J. Daemen and V. Rijmen, AES Proposal: Rijndael, AES Algorithm Submission, September 3, 1999.
\[3\] J. Daemen and V. Rijmen, The block cipher Rijndael, Smart Card research and Applications, LNCS 1820, Springer-Verlag, pp. 288-296.
