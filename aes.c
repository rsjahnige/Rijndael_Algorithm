#include "aes.h"

#define ROT_BYTE(x, n) ((x << n) | (x >> (8 - n))) // Circular left shift of byte x by n bits

/*************************************************
 * Used to initialize constants in AES struct for different
 * key sizes. 
 ************************************************/
int __init__(struct AES* self, int keySize) {
  switch (keySize) {
  case 128:
    self->Nk = 4;
    self->Nr = 10;
    break;
  case 192:
    self->Nk = 6;
    self->Nr = 12;
    break;
  case 256:
    self->Nk = 8;
    self->Nr = 14;
    break;
  default:
    return -1;
  }
  return 0;
}

/*************************************************
 * Struct of word data type used to to store expanded 
 * cipher key. 
 * 
 * Associated functions:
 *    xor() - Bitwise exclusive or of each byte in word
 *    eql() - Set one word equal to another
 ************************************************/ 
static void xor(struct word* result, struct word left, struct word right) {
  result->wd[0] = left.wd[0] ^ right.wd[0];
  result->wd[1] = left.wd[1] ^ right.wd[1];
  result->wd[2] = left.wd[2] ^ right.wd[2];
  result->wd[3] = left.wd[3] ^ right.wd[3];
}

static void eql(struct word* left, struct word right) {
  left->wd[0] = right.wd[0];
  left->wd[1] = right.wd[1];
  left->wd[2] = right.wd[2];
  left->wd[3] = right.wd[3];
}

/**************************************************
 * Auxiliary functions defined to carry out mathematical
 * operations over the finite field GF(2^8)
 * 
 * Functions:
 *    xtime() - Defined in AES specification 
 *    ByteMultiply() - Repeated application of xtime()
 *    EuclidAlgo() - Euclidean Algorithm 
 *    SubByte() - 
 *    InvSubByte() - 
 *************************************************/
static unsigned char xtime(unsigned char x) {
  unsigned char irr_poly = 0x1b;
  unsigned char temp = x;
  
  x <<= 1;
  if (temp > x) // overflow check
    x ^= irr_poly;

  return x;
}

static unsigned char ByteMultiply(unsigned char x, unsigned char y) {
  unsigned short xt = 0x0002;
  unsigned char one = 0x01;
  unsigned char temp = x;
  int iter = 1; // iterator

  if (!(y & one)) // check least significant bit of y
    x = 0x00;
  
  while (xt <= y) {
    temp = xtime(temp);
    if ((y >> iter) & one)
      x ^= temp;
    iter++;
    xt <<= 1;
  }
  
  return x;
}

static unsigned char EuclidAlgo(unsigned short matrix[2][3], int index) {
  int high_bit, iter;
  const unsigned short one = 0x0001;
  unsigned short r = matrix[index][2];  // Remainder
  unsigned short q = 0x0000;  // Quotient
  
  /* Recursion base cases */ 
  if (matrix[0][2] == 0x0001) return (unsigned char)matrix[0][1];
  else if (matrix[1][2] == 0x0001) return (unsigned char)matrix[1][1];
    
  /* Find high bit of divisor */
  for (int i=7; i >= 0; i--) {
    if ((matrix[index ^ 1][2] >> i) & one) {
      high_bit = i;
      break;
    }
  }

  /* One iteration of the Euclidean Algroithm */
  iter = 7; // Set to 7 because remainder and divisor will never be greater than 1 byte
  while (r > matrix[index ^ 1][2]) {
    if ((r >> iter) & one) {
      r ^= (matrix[index ^ 1][2] << (iter - high_bit));
      q ^= (one << (iter - high_bit));
    }
    iter--;
  }

  /* Update Euclidean Matrix */
  matrix[index][2] = r;
  matrix[index][1] ^= ByteMultiply((unsigned char)q, (unsigned char)matrix[index ^ 1][1]);
  return EuclidAlgo(matrix, index ^ 1);
}

static unsigned char SubByte(unsigned char byte) {
  unsigned short euclid_matrix[2][3] = {{0x0001, 0x0000, 0x011b},
					{0x0000, 0x0001, (unsigned short)byte}};
  unsigned char res = 0x00;

  /* Use Euclidean Algorithm to calculate mutiplicative inverse, 
     byte 0x00 is mapped to itself */ 
  if (byte != 0x00) {
    res = EuclidAlgo(euclid_matrix, 0);
  }

  /* Compute affine transformation */
  res ^= ROT_BYTE(res, 1) ^ ROT_BYTE(res, 2) ^ ROT_BYTE(res, 3) ^ ROT_BYTE(res, 4) ^ 0x63;
  
  return res;
}

static unsigned char InvSubByte(unsigned char byte) {
  unsigned short euclid_matrix[2][3] = {{0x0001, 0x0000, 0x011b},
					{0x0000, 0x0001, 0x0000}};

  /* Compute inverse affine transformation */
  byte = ROT_BYTE(byte, 1) ^ ROT_BYTE(byte, 3) ^ ROT_BYTE(byte, 6) ^ 0x05;

  /* Use Euclidean Algorithm to calculate mutiplicative inverse, 
     byte 0x00 is mapped to itself */ 
  if (byte != 0x00) {
    euclid_matrix[1][2] = (unsigned short)byte;
    byte = EuclidAlgo(euclid_matrix, 0);
  }

  return byte;
}


/***************************************************
 * Functions defined for key expansion
 **************************************************/
static void RotWord(struct word* temp) {
  unsigned char tempByte = temp->wd[0];
  temp->wd[0] = temp->wd[1];
  temp->wd[1] = temp->wd[2];
  temp->wd[2] = temp->wd[3];
  temp->wd[3] = tempByte;
}

static void SubWord(struct word* temp) {
  temp->wd[0] = SubByte(temp->wd[0]);
  temp->wd[1] = SubByte(temp->wd[1]);
  temp->wd[2] = SubByte(temp->wd[2]);
  temp->wd[3] = SubByte(temp->wd[3]);
}

int KeyExpansion(struct AES self, unsigned char* key, struct word* w) {
  struct word temp;
  struct word Rcon = {{0x00, 0x00, 0x00, 0x00}};
  
  for (int i=0; i < self.Nk; i++) {
    w[i].wd[0] = key[4*i];
    w[i].wd[1] = key[4*i+1];
    w[i].wd[2] = key[4*i+2];
    w[i].wd[3] = key[4*i+3];
  }
  
  for (int i=self.Nk; i < Nb*(self.Nr+1); i++) { 
    temp.wd[0] = w[i-1].wd[0];
    temp.wd[1] = w[i-1].wd[1];
    temp.wd[2] = w[i-1].wd[2];
    temp.wd[3] = w[i-1].wd[3];
    
    if (i % self.Nk == 0) {
      Rcon.wd[0] = 0x01 << (i/self.Nk-1);
      RotWord(&temp);
      SubWord(&temp);
      xor(&temp, temp, Rcon);
    } else if (self.Nk > 6 && i % self.Nk == 4) {
      SubWord(&temp);
    }

    xor(&w[i], w[i-self.Nk], temp);
  }

  return 0;
}

/*********************************************
 * Functions defined to carry put cipher of plaintex
 * Note: AddRoundKey() is used for both the Cipher and
 *       Inverse Cipher.
 ********************************************/
static void AddRoundKey(unsigned char state[4][Nb], struct word rkey[Nb]) {
  /* XOR columns of state matrix with round key */
  for (int i=0; i < Nb; i++) {
    for (int j=0; j < 4; j++) {
      state[j][i] = state[j][i] ^ rkey[i].wd[j];
    }
  }
}

static void SubBytes(unsigned char state[4][Nb]) {
  for (int i=0; i < 4; i++) {
    for (int j=0; j < Nb; j++) {
      state[i][j] = SubByte(state[i][j]);
    }
  }
}

static void ShiftRows(unsigned char state[4][Nb]) {
  unsigned char row[Nb];
  
  /* Shift row 1 to the left 1 */
  for (int i=0; i < Nb; i++) row[i] = state[1][i];
  for (int i=0; i < Nb; i++) state[1][i] = row[(i+1)%Nb];

  /* Shift row 2 to the left 2 */
  for (int i=0; i < Nb; i++) row[i] = state[2][i];
  for (int i=0; i < Nb; i++) state[2][i] = row[(i+2)%Nb];
  
  /* Shift row 3 to the left 3 */
  for (int i=0; i < Nb; i++) row[i] = state[3][i];
  for (int i=0; i < Nb; i++) state[3][i] = row[(i+3)%Nb];
}

static void MixColumns(unsigned char state[4][Nb]) {
  unsigned char result[4][Nb];
  unsigned char poly[4][4] = {{0x02, 0x03, 0x01, 0x01},
			       {0x01, 0x02, 0x03, 0x01},
			       {0x01, 0x01, 0x02, 0x03},
			       {0x03, 0x01, 0x01, 0x02}};

  /* Initialize result matrix */
  for (int i=0; i < 4; i++) {
    for (int j=0; j < Nb; j++) {
      result[i][j] = 0x00;
    }
  }
  
      
  /* Matrix Multiplication (last row of result is not needed if Nb > 4,
     which allows the state matrix to alter row size if needed) */
  for (int i=0; i < 4; i++) {
    for (int j=0; j < Nb; j++) {
      for (int k=0; k < 4; k++) {
	result[i][j] ^= ByteMultiply(poly[i][k], state[k][j]);
      }
    }
  }

  /* Copy result to state matrix */
  for (int i=0; i < 4; i++) {
    for (int j=0; j < Nb; j++) {
      state[i][j] = result[i][j];
    }
  }
}



int Cipher(struct AES self, unsigned char in[4*Nb], unsigned char out[4*Nb], struct word* w) {
  unsigned char state[4][Nb];
  struct word rkey[Nb]; 

  /* Initialize round key */
  for (int i=0; i < Nb; i++)
    eql(&rkey[i], w[i]);
  
  /* Convert input to a transposed 2D array */
  for (int i=0; i < Nb; i++) {
    for (int j=0; j < 4; j++)
      state[j][i] = in[4*i+j];
  }
  
  AddRoundKey(state, rkey);

  for (int i=1; i < self.Nr; i++) {
    for (int j=0; j < Nb; j++) eql(&rkey[j], w[i*Nb + j]); // Update round key        
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, rkey);
  }

  for (int j=0; j < Nb; j++) eql(&rkey[j], w[self.Nr*Nb + j]); // Update round key  
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, rkey);

  /* Copy state matrix to output */
  for (int i=0; i < Nb; i++) {
    for (int j=0; j < 4; j++) 
      out[4*i+j] = state[j][i];
  }
  
  return 0;
}


/*************************************************
 * Functions defined to carry put inverse cipher of 
 * ciphertext
 ************************************************/
static void InvShiftRows(unsigned char state[4][Nb]) {
  unsigned char row[Nb];
  
  /* Shift row 1 to the right 1 */
  for (int i=0; i < Nb; i++) row[i] = state[1][i];
  for (int i=0; i < Nb; i++) state[1][i] = row[(i+3)%Nb];

  /* Shift row 2 to the right 2 */
  for (int i=0; i < Nb; i++) row[i] = state[2][i];
  for (int i=0; i < Nb; i++) state[2][i] = row[(i+2)%Nb];

  /* Shift row 3 to the right 3 */
  for (int i=0; i < Nb; i++) row[i] = state[3][i];
  for (int i=0; i < Nb; i++) state[3][i] = row[(i+1)%Nb];
}

static void InvSubBytes(unsigned char state[4][Nb]) {
  for (int i=0; i < 4; i++) {
    for (int j=0; j < Nb; j++) {
      if (state[i][j] == 0x63) state[i][j] = 0x00;
      else state[i][j] = InvSubByte(state[i][j]); 
    }}
}

static void InvMixColumns(unsigned char state[4][Nb]) {
  unsigned char result[4][Nb];
  unsigned char poly[4][4] = {{0x0e, 0x0b, 0x0d, 0x09},
			       {0x09, 0x0e, 0x0b, 0x0d},
			       {0x0d, 0x09, 0x0e, 0x0b},
			       {0x0b, 0x0d, 0x09, 0x0e}};

  /* Initialize result matrix */
  for (int i=0; i < 4; i++) {
    for (int j=0; j < Nb; j++)
      result[i][j] = 0x00;
  }
  
  /* Matrix Multiplication (see comment in MixColumns) */
  for (int i=0; i < 4; i++) {
    for(int j=0; j < Nb; j++) {
      for (int k=0; k < 4; k++) {
	result[i][j] ^= ByteMultiply(poly[i][k], state[k][j]);
      }
    }
  }

  /* Copy result to state matrix */
  for (int i=0; i < 4; i++) {
    for (int j=0; j < Nb; j++) {
      state[i][j] = result[i][j];
    }
  }
}

int InvCipher(struct AES self, unsigned char in[4*Nb], unsigned char out[4*Nb], struct word* w) {
  unsigned char state[4][Nb];
  struct word rkey[Nb]; // Round Key
  
  /* Convert input to a transposed 2D array */
  for (int i=0; i < Nb; i++) {
    for (int j=0; j < 4; j++)
      state[j][i] = in[4*i+j];
  }

  for (int i=0; i < Nb; i++) eql(&rkey[i], w[self.Nr*Nb + i]); // Initialize round key
  AddRoundKey(state, rkey);
  
  for (int i=self.Nr - 1; i > 0; i--) {
    for (int j=0; j < Nb; j++) eql(&rkey[j], w[i*Nb + j]); // Update round key
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, rkey);
    InvMixColumns(state);
  }

  for (int i=0; i < Nb; i++) eql(&rkey[i], w[i]); // Update round key
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(state, rkey);

  /* Copy state matrix to output */
  for (int i=0; i < Nb; i++) {
    for (int j=0; j < 4; j++)
      out[4*i+j] = state[j][i];
  }
  
  return 0;
}

