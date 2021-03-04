#include "modes.h"

#define ERR_MSG(msg)			        \
  fprintf(stderr, "Error:%s:%d\n", __FILE__, __LINE__); \
  fprintf(stderr, "\t%s\n", msg);                       \
  fprintf(stderr, "Check Documentation For Assistance");

static struct header {
  unsigned int padding;
  unsigned int mode;
  unsigned int keySize;
  unsigned char newLine;
};

static void gen_iv(unsigned char iv[4*Nb]) {
  time_t seed;
  unsigned long rootMax = 4294967296;
  unsigned long iv_num;

  srandom((unsigned) time(&seed));
  iv_num = (unsigned long) ((random()%rootMax+1)* (random()%rootMax+1));

  for (int i=0; i < 4*Nb; i++)
    iv[i] = (unsigned char)(iv_num >> 4*i);
}

static void pw_exp(const int Nk, const char* pw, unsigned char* key) {
  int size = strlen(pw);
  for (int i=0; i < 4*Nk; i++) key[i] = pw[i%size];
}

ssize_t cbc_enc(const AES params, word* w, unsigned char iv[4*Nb],
		unsigned char block[1024], ssize_t blockSize) {
  unsigned char in[4*Nb];

  if (blockSize % (4*Nb) != 0) {
    blockSize += (4*Nb - (blockSize % (4*Nb)));
  }
  
  for (int i=0; i < blockSize; i += 4*Nb) {
    for (int j=0; j < 4*Nb; j++) block[i+j] ^= iv[j];
    for (int j=0; j < 4*Nb; j++) in[j] = block[i+j];
    Cipher(params, in, iv, w);
    for (int j=0; j < 4*Nb; j++) block[i+j] = iv[j];
  }
  
  return blockSize;
}

ssize_t cbc_dec(const AES params, word* w, unsigned char iv[4*Nb],
		unsigned char block[1024], ssize_t blockSize) {
  unsigned char in[4*Nb];
  unsigned char out[4*Nb];

  if (blockSize % (4*Nb) != 0) {
    ERR_MSG("CBC Decryption Terminated :: Invalid Block Size");
    return -1;
  }
  
  for (int i=0; i < blockSize; i += 4*Nb) {
    for (int j=0; j < 4*Nb; j++) in[j] = block[i+j];
    InvCipher(params, in, out, w);
    for (int j=0; j < 4*Nb; j++) block[i+j] = out[j] ^ iv[j];
    for (int j=0; j < 4*Nb; j++) iv[j] = in[j];
  }

  return blockSize;
}

int encrypt_file(const char* fileName, const char* pw,
		  const int mode, const int keySize) {
  AES params;
  word* w;
  int fd_pt, fd_enc;
  off_t pt_size, pt_off;
  size_t size;
  ssize_t r_bytes, e_bytes;
  char* file_name;
  unsigned char* key;
  unsigned char block[1024];
  unsigned char iv[4*Nb], iv_enc[4*Nb];
  char null_bytes[1024] = {'\0'};
  struct header head = {0, mode, keySize, '\n'}; 

  if(__init__(&params, keySize) < 0) {
    ERR_MSG("Encryption Terminated :: Invalid Key Size Provided");
    goto exit_error;
  }
  
  if ((fd_pt = open(fileName, O_RDWR)) < 0) {
    ERR_MSG("Encryption Terminated :: Input File Does Not Exist");
    goto exit_error;
  }

  size = strlen(fileName);
  file_name = malloc(size+4);
  memcpy(file_name, fileName, size);
  memcpy(file_name+size, ".enc", 4);

  if ((fd_enc = open(file_name, O_RDONLY)) != -1) {
    ERR_MSG("Encryption Terminated :: Output File Already Exists: Cannot Overwrite");
    goto exit_FEX;
  } else {
    fd_enc = open(file_name, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
  }

  w = malloc(sizeof(word)*Nb*(params.Nr+1));
  key = malloc(4*params.Nk);
  
  pw_exp(params.Nk, pw, key);
  KeyExpansion(params, key, w);

  r_bytes = read(fd_pt, block, 1024);
  pt_size = r_bytes;
  write(fd_enc, &head, sizeof(struct header));

  switch (mode) {
  case CBC:
    gen_iv(iv);
    Cipher(params, iv, iv_enc, w);
    write(fd_enc, iv_enc, 4*Nb);

    while (r_bytes == 1024) {
      e_bytes = cbc_enc(params, w, iv, block, r_bytes);
      write(fd_enc, block, e_bytes);
      r_bytes = read(fd_pt, block, 1024);
      pt_size += r_bytes;
    }

    if (r_bytes != 0) {
      e_bytes = cbc_enc(params, w, iv, block, r_bytes);
      write(fd_enc, block, e_bytes);
    }
    break;
  default:
    ERR_MSG("Encryption Terminated :: Invalid Mode Provided");
    goto exit_MD;
  }

  // Determine padding and add to header
  lseek(fd_enc, 0, SEEK_SET);
  head.padding = (unsigned int)(e_bytes - r_bytes);
  write(fd_enc, &head.padding, sizeof(unsigned int));

  // Overwrite plaintext file with null bytes
  pt_off = lseek(fd_pt, 0, SEEK_SET);
  while (pt_off <= pt_size)
    pt_off += write(fd_pt, null_bytes, 1024);
  
  // Clean Up
  free(key);
  free(w);
  close(fd_enc);
  close(fd_pt);
  remove(fileName);
  return 0;

 exit_MD:
  free(key);
  free(w);
  remove(file_name);
 exit_FEX:
  close(fd_enc);
  free(file_name);
  close(fd_pt);
 exit_error:
  return -1;
}

int decrypt_file(const char* fileName, const char* pw) {
  AES params;
  word* w;
  int fd_enc, fd_pt;
  size_t size;
  ssize_t r_bytes;
  off_t w_offset = 0;
  char *file_name;
  unsigned char* key;
  unsigned char iv[4*Nb], enc_iv[4*Nb];
  unsigned char block[1024];
  struct header head;

  if ((fd_enc = open(fileName, O_RDWR)) == -1) {
    ERR_MSG("Decryption Terminated :: Input File Does Not Exist");
    goto exit_error;
  }

  r_bytes = read(fd_enc, &head, sizeof(struct header));
  if (__init__(&params, head.keySize) < 0) {
    ERR_MSG("Decryption Terminated :: Invalid Key Size: Check Input File Format");
    goto exit_KSZ;
  }
  
  size = strlen(fileName) - 4;
  file_name = malloc(size);
  memcpy(file_name, fileName, size);

  if ((fd_pt = open(file_name, O_RDONLY)) != -1) {
    ERR_MSG("Decryption Terminated :: Output File Already Exists: Cannot Overwrite");
    goto exit_FEX;
  } else {
    fd_pt = open(file_name, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
  }

  w = malloc(sizeof(word)*Nb*(params.Nr+1));
  key = malloc(4*params.Nk);

  pw_exp(params.Nk, pw, key);  
  KeyExpansion(params, key, w);

  switch (head.mode) {
  case CBC:
    r_bytes = read(fd_enc, enc_iv, 4*Nb);
    InvCipher(params, enc_iv, iv, w);

    r_bytes = read(fd_enc, block, 1024);
    while (r_bytes != 0) {
      cbc_dec(params, w, iv, block, r_bytes);
      w_offset += write(fd_pt, block, r_bytes);
      r_bytes = read(fd_enc, block, 1024);
    }

    ftruncate(fd_pt, w_offset-head.padding);
    break;
  default:
    ERR_MSG("Decryption Terminated :: Invalid Mode: Check Input File Format");
    goto exit_MD;
  }

  // Clean Up
  free(key);
  free(w);
  close(fd_pt);
  free(file_name);
  close(fd_enc);
  remove(fileName);
  return 0;

 exit_MD:
  free(key);
  free(w);
  remove(file_name);
 exit_FEX:
  close(fd_pt);
  free(file_name);
 exit_KSZ:
  close(fd_enc);
 exit_error:
  return -1;
}
