#ifndef __SPARSEBUNDLEUTIL_H__

#define __SPARSEBUNDLEUTIL_H__		1

/* length of message digest output in bytes (160 bits) */
#define MD_LENGTH		20
/* length of cipher key in bytes (128 bits) */
#define CIPHER_KEY_LENGTH	16
/* block size of cipher in bytes (128 bits) */
#define CIPHER_BLOCKSIZE	16
/* chunk size (FileVault specific) */
//#define CHUNK_SIZE		4096
/* number of iterations for PBKDF2 key derivation */
//#define PBKDF2_ITERATION_COUNT	1000


#ifdef __APPLE__
	#include <libkern/OSByteOrder.h>
	#define htobe32(x) OSSwapHostToBigInt32(x)
	#define be32toh(x) OSSwapBigToHostInt32(x)
	#define be64toh(x) OSSwapBigToHostInt64(x)
#endif

void print_hex(void *data, uint32_t len, const char* format, ...) __attribute__ ((__format__ (__printf__, 3, 4)));
void convert_hex(char * /* str */, uint8_t * /* bytes */, int /* maxlen */);


#endif
