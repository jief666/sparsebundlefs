#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <pwd.h>

#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "sparsebundleutil.h"
#include "v2header.h"

#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64


void dump_v2_header(cencrypted_v2_header *v2header)
{
	syslog(LOG_DEBUG, "V2 HEADER :");
	syslog(LOG_DEBUG, "sig %s", v2header->sig);
	syslog(LOG_DEBUG, "blocksize %u", v2header->blocksize);
	syslog(LOG_DEBUG, "datasize %llu", v2header->datasize);
	syslog(LOG_DEBUG, "dataoffset %llu", v2header->dataoffset);
	syslog(LOG_DEBUG, "keycount %u", v2header->keycount);
}

void dump_v2_key_header(cencrypted_v2_key_header_pointer *v2header)
{
	syslog(LOG_DEBUG, "V2 KEY HEADER :");
	syslog(LOG_DEBUG, "header_type %d", v2header->header_type);
	syslog(LOG_DEBUG, "header_offset %d", v2header->header_offset);
	syslog(LOG_DEBUG, "header_size %d", v2header->header_size);
}

void dump_v2_password_header(cencrypted_v2_password_header *pwhdr)
{
	syslog(LOG_DEBUG, "V2 PASSWORD HEADER :");
	/* 103: CSSM_ALGID_PKCS5_PBKDF2 */
	syslog(LOG_DEBUG, "keyDerivationAlgorithm      %lu", (unsigned long) pwhdr->kdf_algorithm);
	syslog(LOG_DEBUG, "keyDerivationPRNGAlgorithm  %lu", (unsigned long) pwhdr->kdf_prng_algorithm);
	/* by default the iteration count should be 1000 iterations */
	syslog(LOG_DEBUG, "keyDerivationIterationCount %lu", (unsigned long) pwhdr->kdf_iteration_count);
	syslog(LOG_DEBUG, "keyDerivationSaltSize       %lu", (unsigned long) pwhdr->kdf_salt_len);
	print_hex(pwhdr->kdf_salt, sizeof(pwhdr->kdf_salt), "keyDerivationSalt           ");
	syslog(LOG_DEBUG, "blobEncryptionIVSize        %lu", (unsigned long) pwhdr->blob_enc_iv_size);
	syslog(LOG_DEBUG, "blobEncryptionIV            ");
	//	print_hex(pwhdr->blob_enc_iv, pwhdr->blob_enc_iv_size);
	print_hex(pwhdr->blob_enc_iv, sizeof(pwhdr->blob_enc_iv), "blobEncryptionIV            ");
	syslog(LOG_DEBUG, "blobEncryptionKeySizeInBits %lu",  (unsigned long) pwhdr->blob_enc_key_bits);
	/*  17: CSSM_ALGID_3DES_3KEY_EDE */
	syslog(LOG_DEBUG, "blobEncryptionAlgorithm     %lu",  (unsigned long) pwhdr->blob_enc_algorithm);
	/*   7: CSSM_PADDING_PKCS7 */
	syslog(LOG_DEBUG, "blobEncryptionPadding       %lu",  (unsigned long) pwhdr->blob_enc_padding);
	/*   6: CSSM_ALGMODE_CBCPadIV8 */
	syslog(LOG_DEBUG, "blobEncryptionMode          %lu",  (unsigned long)  pwhdr->blob_enc_mode);
	syslog(LOG_DEBUG, "encryptedBlobSize           %lu",  (unsigned long)  pwhdr->encrypted_keyblob_size);
	print_hex(pwhdr->encrypted_keyblob, pwhdr->encrypted_keyblob_size, "encryptedBlob               ");
}

#ifdef __OSX__
#define be32toh(x) OSSwapHostToBigInt32(x)
#endif

//#define swap32(x) x = OSSwapHostToBigInt32(x)
//#define swap64(x) x = ((uint64_t) ntohl(x >> 32)) | (((uint64_t) ntohl((uint32_t) (x & 0xFFFFFFFF))) << 32)

void adjust_v2_header_byteorder(cencrypted_v2_header *v2header)
{
	v2header->blocksize = be32toh(v2header->blocksize);
	v2header->datasize = be64toh(v2header->datasize);
	v2header->dataoffset = be64toh(v2header->dataoffset);
	v2header->keycount = be32toh(v2header->keycount);
}

void adjust_v2_key_header_pointer_byteorder(cencrypted_v2_key_header_pointer *key_header_pointer)
{
	key_header_pointer->header_type = htonl(key_header_pointer->header_type);
	key_header_pointer->header_offset = htonl(key_header_pointer->header_offset);
	key_header_pointer->header_size = htonl(key_header_pointer->header_size);
}

void adjust_v2_password_header_byteorder(cencrypted_v2_password_header *pwhdr)
{
	pwhdr->kdf_algorithm = htonl(pwhdr->kdf_algorithm);
	pwhdr->kdf_prng_algorithm = htonl(pwhdr->kdf_prng_algorithm);
	pwhdr->kdf_iteration_count = htonl(pwhdr->kdf_iteration_count);
	pwhdr->kdf_salt_len = htonl(pwhdr->kdf_salt_len);
	pwhdr->blob_enc_iv_size = htonl(pwhdr->blob_enc_iv_size);
	pwhdr->blob_enc_key_bits = htonl(pwhdr->blob_enc_key_bits);
	pwhdr->blob_enc_algorithm = htonl(pwhdr->blob_enc_algorithm);
	pwhdr->blob_enc_padding = htonl(pwhdr->blob_enc_padding);
	pwhdr->blob_enc_mode = htonl(pwhdr->blob_enc_mode);
	pwhdr->encrypted_keyblob_size = htonl(pwhdr->encrypted_keyblob_size);
}







int unwrap_v2_password_header(cencrypted_v2_password_header *pwhdr, uint8_t *hmacsha1_key, uint8_t *aes_key, uint8_t*aes_key_size_ptr, const char* password)
{
	/* derived key is a 3DES-EDE key */
	uint8_t derived_key[192/8];
	EVP_CIPHER_CTX ctx;
	int outlen, tmplen;


	if ( password != NULL ) {
		PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), (unsigned char*)pwhdr->kdf_salt, pwhdr->kdf_salt_len, pwhdr->kdf_iteration_count, sizeof(derived_key), derived_key);
	}else{
		char *aPassword = getpass("Password: ");
		PKCS5_PBKDF2_HMAC_SHA1(aPassword, strlen(aPassword), (unsigned char*)pwhdr->kdf_salt, pwhdr->kdf_salt_len, pwhdr->kdf_iteration_count, sizeof(derived_key), derived_key);
		memset(aPassword, 0, strlen(aPassword));
	}

print_hex(derived_key, 192/8, "derived_key : ");

	if ( pwhdr->encrypted_keyblob_size == 48 ) {
		*aes_key_size_ptr = 16;
	}else if ( pwhdr->encrypted_keyblob_size == 64 ) {
		*aes_key_size_ptr = 32;
	}


	EVP_CIPHER_CTX_init(&ctx);
	/* result of the decryption operation shouldn't be bigger than ciphertext */
	uint8_t TEMP1[pwhdr->encrypted_keyblob_size];
	/* uses PKCS#7 padding for symmetric key operations by default */
	EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, derived_key, pwhdr->blob_enc_iv);

	if(!EVP_DecryptUpdate(&ctx, TEMP1, &outlen, pwhdr->encrypted_keyblob, pwhdr->encrypted_keyblob_size)) {
		syslog(LOG_DEBUG, "internal error (1) during key unwrap operation!");
		return(-1);
	}
	if(!EVP_DecryptFinal_ex(&ctx, TEMP1 + outlen, &tmplen)) {
		syslog(LOG_DEBUG, "internal error (2) during key unwrap operation!");
		return(-1);
	}
	outlen += tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	memcpy(aes_key, TEMP1, *aes_key_size_ptr);
	memcpy(hmacsha1_key, TEMP1+*aes_key_size_ptr, HMACSHA1_KEY_SIZE);

print_hex(aes_key, *aes_key_size_ptr, "aes_key(%d) : ", *aes_key_size_ptr*8);
print_hex(hmacsha1_key, HMACSHA1_KEY_SIZE, "hmacsha1_key : ");

	return(0);
}

int v2_read_token(const char* path, cencrypted_v2_header *v2headerPtr, uint8_t* hmacsha1_key_ptr, uint8_t* aes_key_ptr, uint8_t*aes_key_size_ptr, const char* password )
{
	char token_filename[MAXPATHLEN];
	int fd_token;
	sprintf(token_filename, "%s/token", path);
	if ((fd_token = open(token_filename, O_RDONLY)) < 0) {
		syslog(LOG_DEBUG, "Error: unable to open %s", token_filename);
		exit(EXIT_FAILURE);
	}

	//cencrypted_v2_header& v2header = *v2headerPtr;
#define v2header (*v2headerPtr)
	cencrypted_v2_key_header_pointer v2keyheader;
	cencrypted_v2_password_header v2pwhdr;
	//uint8_t hmacsha1_key[HMACSHA1_KEY_SIZE];
	//uint8_t aes_key[AES_KEY_SIZE];

	int password_header_found = 0;

	lseek(fd_token, 0L, SEEK_SET);
	if ( read(fd_token, &v2header, sizeof(v2header)) != sizeof(v2header) ) {
		syslog(LOG_DEBUG, "header corrupted?");
		exit(EXIT_FAILURE);
	}
	adjust_v2_header_byteorder(&v2header);
	dump_v2_header(&v2header);
	if ( strcmp(v2header.sig, "encrcdsa") != 0 ) {
		syslog(LOG_DEBUG, "signature should be encrcdsa. Header corrupted? (sig=%s)", v2header.sig);
		exit(EXIT_FAILURE);
	}
	uint32_t i;
	for ( i = 0; i < v2header.keycount; i++) {
		// Seek to the start of the key header pointers offset by the current key which start immediately after the v2 header.
		if (lseek(fd_token, sizeof(v2header) + (sizeof(v2keyheader)*i), SEEK_SET) != sizeof(v2header) + (sizeof(v2keyheader)*i) ) {
			syslog(LOG_DEBUG, "Unable to seek to header pointers in %s", token_filename);
			exit(EXIT_FAILURE);
		}

		// Read in the key header pointer
		ssize_t count = read(fd_token, &v2keyheader, sizeof(v2keyheader));
		if (count != sizeof(v2keyheader)) {
			syslog(LOG_DEBUG, "Unable to read key header from %s (sizeof(v2keyheaderptr)=%zd count=%zd)", token_filename, sizeof(v2keyheader), count);
			exit(EXIT_FAILURE);
		}

		adjust_v2_key_header_pointer_byteorder(&v2keyheader);
		dump_v2_key_header(&v2keyheader);

		// We, currently, only care about the password key header. If it's not the password header type skip over it.
		if (v2keyheader.header_type != 1) {
			continue;
		}

		password_header_found = 1;

		// Seek to where the password key header is in the file.
		if (lseek(fd_token, v2keyheader.header_offset, SEEK_SET) != v2keyheader.header_offset ) {
			syslog(LOG_DEBUG, "Unable to seek to password header in %s", token_filename);
			exit(EXIT_FAILURE);
		}

		// Read in the password key header but avoid reading anything into the keyblob.
		count = read(fd_token, &v2pwhdr, sizeof(v2pwhdr) - sizeof(unsigned char *));
		if (count != sizeof(v2pwhdr) - sizeof(unsigned char *)) {
			syslog(LOG_DEBUG, "Unable to read password header from %s", token_filename);
			exit(EXIT_FAILURE);
		}

		adjust_v2_password_header_byteorder(&v2pwhdr);
		// Allocate the keyblob memory
		v2pwhdr.encrypted_keyblob = (uint8_t*)malloc(v2pwhdr.encrypted_keyblob_size);

		// Seek to the keyblob in the header
		if (lseek(fd_token, v2keyheader.header_offset + sizeof(v2pwhdr) - sizeof(unsigned char *), SEEK_SET) != v2keyheader.header_offset + sizeof(v2pwhdr) - sizeof(unsigned char *) ) {
			syslog(LOG_DEBUG, "Unable to seek to password header in %s", token_filename);
			free(v2pwhdr.encrypted_keyblob);
			exit(EXIT_FAILURE);
		}

		// Read in the keyblob
		count = read(fd_token, v2pwhdr.encrypted_keyblob, v2pwhdr.encrypted_keyblob_size);
		if (count != (ssize_t)v2pwhdr.encrypted_keyblob_size) {
			syslog(LOG_DEBUG, "Unable to read blob from %s (v2pwhdr.encrypted_keyblob_size=%u)", token_filename, v2pwhdr.encrypted_keyblob_size);
			free(v2pwhdr.encrypted_keyblob);
			exit(EXIT_FAILURE);
		}
		dump_v2_password_header(&v2pwhdr);
		if ( unwrap_v2_password_header(&v2pwhdr, hmacsha1_key_ptr, aes_key_ptr, aes_key_size_ptr, password) == -1 ) {
			syslog(LOG_DEBUG, "Unable to unwrap. Wrong password ?");
			fprintf(stderr, "Unable to unwrap. Wrong password ?\n");
			exit(EXIT_FAILURE);
		}


		// We only need one password header. Don't search any longer.
		break;
	}

	if (!password_header_found) {
		syslog(LOG_DEBUG, "Password header not found in %s", token_filename);
		exit(EXIT_FAILURE);
	}

	if (v2pwhdr.kdf_salt_len > 32) {
		syslog(LOG_DEBUG, "%s is not a valid DMG file, salt length is too long!", token_filename);
		free(v2pwhdr.encrypted_keyblob);
		exit(EXIT_FAILURE);
	}

syslog(LOG_DEBUG, "%s (DMG v%d) successfully parsed, iterations count %u", token_filename, 2, v2pwhdr.kdf_iteration_count);


	return 0;
}
