#ifndef __V2HEADER_H__

#define __V2HEADER_H__		1

//#define AES_KEY_SIZE 16
#define HMACSHA1_KEY_SIZE 20

typedef struct __attribute__((packed)) {
  char sig[8];
  uint32_t version;
  uint32_t enc_iv_size;
  uint32_t encMode;
  uint32_t encAlg;
  uint32_t keyBits;
  uint32_t prngalg;
  uint32_t prngkeysize;
  unsigned char uuid[16];
  uint32_t blocksize;
  uint64_t datasize;
  uint64_t dataoffset;
  uint32_t keycount;
} cencrypted_v2_header;

typedef struct __attribute__((packed)) {
    uint32_t header_type;
    uint32_t unk1;
    uint32_t header_offset;
    uint32_t unk2;
    uint32_t header_size;
} cencrypted_v2_key_header_pointer;

typedef struct __attribute__((packed)) {
  uint32_t kdf_algorithm;
  uint32_t kdf_prng_algorithm;
  uint32_t kdf_iteration_count;
  uint32_t kdf_salt_len; /* in bytes */
  uint8_t  kdf_salt[32];
  uint32_t blob_enc_iv_size;
  uint8_t  blob_enc_iv[32];
  uint32_t blob_enc_key_bits;
  uint32_t blob_enc_algorithm;
  uint32_t blob_enc_padding;
  uint32_t blob_enc_mode;
  uint32_t encrypted_keyblob_size;
  uint8_t*  encrypted_keyblob;
} cencrypted_v2_password_header;

void dump_v2_header(cencrypted_v2_header * /* hdr */);
void dump_v2_key_header(cencrypted_v2_key_header_pointer *v2header);
void dump_v2_password_header(cencrypted_v2_password_header * /* pwhdr */);

void adjust_v2_header_byteorder(cencrypted_v2_header * /* pwhdr */);
void adjust_v2_key_header_pointer_byteorder(cencrypted_v2_key_header_pointer *key_header_pointer);
void adjust_v2_password_header_byteorder(cencrypted_v2_password_header *pwhdr);

int v2_read_token(const char* path, cencrypted_v2_header *v2headerPtr, uint8_t* hmacsha1_key_ptr, uint8_t* aes_key_ptr, uint8_t*aes_key_size_ptr, const char* password);

#endif
