#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 26

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <assert.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <pwd.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <streambuf>
#include <string>
#include <vector>


#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "sparsebundle.h"
#include "sparsebundleutil.h"
#include "v2header.h"

#include <fuse.h>

//#define FUSE_SUPPORTS_ZERO_COPY FUSE_VERSION >= 29

static const char image_path[] = "/sparsebundle.dmg";




struct sparsebundle_data
{
	bool encrypted;
    char *path;
    bool headeronly;
    char* password;
    off_t band_size;
    size_t blocksize;
    off_t size;
    off_t times_opened;
    HMAC_CTX hmacsha1_ctx;
    uint8_t hmacsha1_key[HMACSHA1_KEY_SIZE];
    uint8_t aes_key[32]; // up to aes 256 bits
    uint8_t aes_key_size;
    AES_KEY aes_decrypt_key;
#if FUSE_SUPPORTS_ZERO_COPY
    map<string, int> open_files;
#endif
};

struct sparsebundle_read_operations {
    int (*process_band) (const char *band_path, size_t length, off_t offset, char* buff, sparsebundle_data* sparsebundle_data);
    int (*pad_with_zeroes) (size_t length, void *buff);
    char *data;
};




/**
 * Compute IV of current block as
 * truncate128(HMAC-SHA1(hmacsha1key||blockno))
 */
void compute_iv(uint32_t chunk_no, uint8_t *iv, sparsebundle_data* sparsebundle_data)
{
	unsigned char mdResult[MD_LENGTH];
	unsigned int mdLen;

	chunk_no = htobe32(chunk_no);
	HMAC_Init_ex(&(sparsebundle_data->hmacsha1_ctx), NULL, 0, NULL, NULL);
	HMAC_Update(&(sparsebundle_data->hmacsha1_ctx), (const unsigned char *) &chunk_no, sizeof(uint32_t));
	HMAC_Final(&(sparsebundle_data->hmacsha1_ctx), mdResult, &mdLen);
	memcpy(iv, mdResult, CIPHER_BLOCKSIZE);
}

void decrypt_chunk(void *ctext, void *ptext, uint32_t chunk_no, sparsebundle_data* sparsebundle_data)
{
	uint8_t iv[CIPHER_BLOCKSIZE];

	compute_iv(chunk_no, iv, sparsebundle_data);
print_hex(iv, CIPHER_BLOCKSIZE, "decrypt_chunk  chunk_no=%d, iv=", chunk_no);
	AES_cbc_encrypt((uint8_t *)ctext, (uint8_t *)ptext, sparsebundle_data->blocksize, &(sparsebundle_data->aes_decrypt_key), iv, AES_DECRYPT);
}




using namespace std;




int sparsebundle_iterate_bands(size_t length, off_t offset, struct sparsebundle_read_operations *read_ops, sparsebundle_data* sparsebundle_data)
{
    if (offset >= sparsebundle_data->size)
        return 0;

    if (offset + length > sparsebundle_data->size) {
        length = sparsebundle_data->size - offset;
    }

    syslog(LOG_DEBUG, "iterating %zu bytes at offset %"PRId64, length, offset);

    size_t bytes_read = 0;
    while (bytes_read < length) {
        off_t band_number = (offset + bytes_read) / sparsebundle_data->band_size;
        off_t band_offset = (offset + bytes_read) % sparsebundle_data->band_size;

        ssize_t to_read = min( (off_t)(length - bytes_read), sparsebundle_data->band_size - band_offset);

        char *band_path;
        if (asprintf(&band_path, "%s/bands/%"PRIx64, sparsebundle_data->path, band_number) == -1) {
            syslog(LOG_ERR, "failed to resolve band name");
            return -errno;
        }

        syslog(LOG_DEBUG, "processing %zu/%zu bytes from band %"PRId64" at offset %"PRId64, to_read, bytes_read, band_number, band_offset);

        ssize_t read = read_ops->process_band(band_path, to_read, band_offset, read_ops->data+bytes_read, sparsebundle_data);
        if (read < 0) {
            free(band_path);
            return -1;
        }

        free(band_path);

        if (read < to_read) {
            ssize_t to_pad = to_read - read;
            syslog(LOG_DEBUG, "missing %zd bytes from band %"PRId64", padding with zeroes (bytes_read=%zd, to_read=%zd, read=%zd)", to_pad, band_number, bytes_read, to_read, read);
            if ( to_pad+bytes_read+read > length ) {
            	exit(1);
            }
            read += read_ops->pad_with_zeroes(to_pad, read_ops->data+bytes_read+read);
        }

        bytes_read += read;

        syslog(LOG_DEBUG, "done processing band %"PRId64", %zd bytes left to read", band_number, length - bytes_read);
    }

    assert(bytes_read == length);
    return bytes_read;
}

static int sparsebundle_read_process_band_not_encrypted(const char *band_path, size_t length, off_t offset, char* buff, sparsebundle_data* sparsebundle_data)
{
    ssize_t read = 0;

    syslog(LOG_DEBUG, "reading %zu bytes at offset %"PRId64" into %p", length, offset, buff);

    int band_file = open(band_path, O_RDONLY);
    if (band_file != -1) {
        read = pread(band_file, buff, length, offset);
        close(band_file);

        if (read == -1) {
            syslog(LOG_ERR, "failed to read band: %s", strerror(errno));
            return -errno;
        }
    } else if (errno != ENOENT) {
        syslog(LOG_ERR, "failed to open band %s: %s", band_path, strerror(errno));
        return -errno;
    }

    return read;
}

static int sparsebundle_read_process_band_encrypted(const char *band_path, size_t length, off_t offset, char* buff, sparsebundle_data* sparsebundle_data)
{
syslog(LOG_DEBUG, "ENTER - sparsebundle_read_process_band_encrypted band_path=%s - length=%zu - offset %" PRId64, band_path, length, offset);
    off_t block_number = offset/512;
syslog(LOG_DEBUG, "sparsebundle_read_process_band_encrypted block number  %" PRId64, block_number);
    off_t block_offset = block_number * 512;
syslog(LOG_DEBUG, "sparsebundle_read_process_band_encrypted block_offset  %" PRId64, block_offset);
    off_t delta_offset = offset - block_offset;
syslog(LOG_DEBUG, "sparsebundle_read_process_band_encrypted delta_offset  %" PRId64, delta_offset);
    char inbuf[sparsebundle_data->blocksize];

    ssize_t readtotal = 0;

    syslog(LOG_DEBUG, "reading %zu bytes at offset %"PRId64" into %p", length, offset, buff);

    int band_file = open(band_path, O_RDONLY);
    if (band_file != -1)
    {
    	while (length > 0)
    	{
    		size_t to_copy = min(length, sparsebundle_data->blocksize);
syslog(LOG_DEBUG, "delta_offset == %lld reading %zu bytes at offset %lld into %p", delta_offset, sparsebundle_data->blocksize, block_offset, buff);
    		if ( delta_offset != 0  ||  to_copy < sparsebundle_data->blocksize ) {
				ssize_t nbread = pread(band_file, inbuf, sparsebundle_data->blocksize, block_offset);
                if (nbread != (ssize_t)sparsebundle_data->blocksize ) {
                    syslog(LOG_ERR, "failed to read band 1 %s, offset %"PRId64", length %zd: nbread=%zu errno=%s;%d", band_path, block_offset, sparsebundle_data->blocksize, nbread, strerror(errno), errno);
                    close(band_file);
                    if ( nbread < 0 ) {
                    	syslog(LOG_DEBUG, "LEAVE - sparsebundle_read_process_band_encrypted band_path=%s - length=%zu - offset %"PRId64" -- returns %zu", band_path, length, offset, nbread);
                    	return nbread;
                    }
                    syslog(LOG_DEBUG, "LEAVE - sparsebundle_read_process_band_encrypted band_path=%s - length=%zu - offset %"PRId64" -- returns %zu", band_path, length, offset, readtotal);
                    return readtotal;
                }
                char outbuf[sparsebundle_data->blocksize];
            	decrypt_chunk(inbuf, outbuf, block_number, sparsebundle_data);
            	memcpy(buff, outbuf+delta_offset, to_copy);
    		}else{
    			ssize_t nbread = pread(band_file, inbuf, sparsebundle_data->blocksize, block_offset);
                if (nbread != (ssize_t)sparsebundle_data->blocksize ) {
                    syslog(LOG_ERR, "failed to read band 2 %s, offset %"PRId64", length %zd: nbread=%zu errno=%s;%d", band_path, block_offset, sparsebundle_data->blocksize, nbread, strerror(errno), errno);
                    close(band_file);
                    if ( nbread < 0 ) {
                    	syslog(LOG_DEBUG, "LEAVE - sparsebundle_read_process_band_encrypted band_path=%s - length=%zu - offset %"PRId64" -- returns %zu", band_path, length, offset, nbread);
                    	return nbread;
                    }
                    syslog(LOG_DEBUG, "LEAVE - sparsebundle_read_process_band_encrypted band_path=%s - length=%zu - offset %"PRId64" -- returns %zu", band_path, length, offset, readtotal);
                    return readtotal;
                }
//syslog(LOG_DEBUG, "12 sparsebundle_data->blocksize=%lu", sparsebundle_data->blocksize);
print_hex(inbuf, 32, "block %"PRId64" - offsset %"PRId64" %"PRIx64" crypted : ", block_offset/sparsebundle_data->blocksize, block_offset, block_offset);
            	decrypt_chunk(inbuf, buff, block_number, sparsebundle_data);
print_hex(buff, 32, "block %"PRId64" - offsset %"PRId64" %"PRIx64" decrypt : ", block_offset/sparsebundle_data->blocksize, block_offset, block_offset);
    		}
        	buff += to_copy;
        	readtotal += to_copy;
        	length -= to_copy;
        	block_offset += sparsebundle_data->blocksize;
        	block_number += 1;
        	delta_offset = 0;
    	}
        close(band_file);
        return readtotal;
    }
    else if (errno != ENOENT) {
        syslog(LOG_ERR, "failed to open band %s: %s", band_path, strerror(errno));
        return -1;
    }
    // never goes here, but compiler complains.
    return -1;
}

static int sparsebundle_read_pad_with_zeroes(size_t length, void *buff)
{
    syslog(LOG_DEBUG, "padding %zu bytes of zeroes into %p", length, buff);
    memset(buff, 0, length);
    return length;
}


#define SB_DATA_CAST(ptr) ((struct sparsebundle_data *) ptr)
#define SB_DATA (SB_DATA_CAST(fuse_get_context()->private_data))


static int sparsebundle_getattr(const char *path, struct stat *stbuf)
{
syslog(LOG_DEBUG, "sparsebundle_getattr");
    memset(stbuf, 0, sizeof(struct stat));

    struct stat bundle_stat;
    stat(SB_DATA->path, &bundle_stat);

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0555;
        stbuf->st_nlink = 3;
        stbuf->st_size = sizeof(sparsebundle_data);
    } else if (strcmp(path, image_path) == 0) {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = SB_DATA->size;
    } else
        return -ENOENT;

    stbuf->st_atime = bundle_stat.st_atime;
    stbuf->st_mtime = bundle_stat.st_mtime;
    stbuf->st_ctime = bundle_stat.st_ctime;

    return 0;
}


static int sparsebundle_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
syslog(LOG_DEBUG, "sparsebundle_readdir");

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    struct stat image_stat;
    sparsebundle_getattr(image_path, &image_stat);

    filler(buf, ".", 0, 0);
    filler(buf, "..", 0, 0);
    filler(buf, image_path + 1, &image_stat, 0);

    return 0;
}

static int sparsebundle_open(const char *path, struct fuse_file_info *fi)
{
syslog(LOG_DEBUG, "sparsebundle_open");
    if (strcmp(path, image_path) != 0)
        return -ENOENT;

    if ((fi->flags & O_ACCMODE) != O_RDONLY)
        return -EACCES;

    SB_DATA->times_opened++;
    syslog(LOG_DEBUG, "opened %s, now referenced %"PRId64" times", SB_DATA->path, SB_DATA->times_opened);

    return 0;
}


static int sparsebundle_read_not_encrypted(const char *path, char *buffer, size_t length, int64_t offset, struct fuse_file_info *fi)
{
syslog(LOG_DEBUG, "sparsebundle_read_not_encrypted  length=%zu  offset=%llu", length, offset);
    sparsebundle_read_operations read_ops = {
        &sparsebundle_read_process_band_not_encrypted,
        sparsebundle_read_pad_with_zeroes,
        buffer
    };

    syslog(LOG_DEBUG, "asked to read %zu bytes at offset %"PRId64, length, offset);

    if (strcmp(path, image_path) != 0) return -ENOENT;

    return sparsebundle_iterate_bands(length, offset, &read_ops, SB_DATA);
}

static int sparsebundle_read_encrypted(const char *path, char *buffer, size_t length, int64_t offset, struct fuse_file_info *fi)
{
syslog(LOG_DEBUG, "sparsebundle_read_encrypted  length=%zu  offset=%llu", length, offset);
    sparsebundle_read_operations read_ops = {
        &sparsebundle_read_process_band_encrypted,
        sparsebundle_read_pad_with_zeroes,
        buffer
    };

    syslog(LOG_DEBUG, "asked to read %zu bytes at offset %"PRId64, length, offset);

    if (strcmp(path, image_path) != 0) return -ENOENT;

    return sparsebundle_iterate_bands(length, offset, &read_ops, SB_DATA);
}


static int sparsebundle_read_not_fuse(const char *path, char *buffer, size_t length, off_t offset, sparsebundle_data* sparsebundle_data)
{
    sparsebundle_read_operations read_ops = {
        &sparsebundle_read_process_band_not_encrypted,
        sparsebundle_read_pad_with_zeroes,
        buffer
    };
    if ( sparsebundle_data->encrypted ) {
    	read_ops.process_band = &sparsebundle_read_process_band_encrypted;
    }

    syslog(LOG_DEBUG, "asked to read %zu bytes at offset %"PRId64, length, offset);

    return sparsebundle_iterate_bands(length, offset, &read_ops, sparsebundle_data);
}

#if FUSE_SUPPORTS_ZERO_COPY
#error sdfdsqf
int sparsebundle_read_buf_prepare_file(const char *path)
{
    int fd = -1;
    map<string, int>::const_iterator iter = SB_DATA->open_files.find(path);
    if (iter != SB_DATA->open_files.end()) {
        fd = iter->second;
    } else {
        syslog(LOG_DEBUG, "file %s not opened yet, opening", path);
        fd = open(path, O_RDONLY);
        SB_DATA->open_files[path] = fd;
    }

    return fd;
}

static int sparsebundle_read_buf_process_band(const char *band_path, size_t length, off_t offset, void *read_data)
{
    ssize_t read = 0;

    vector<fuse_buf> *buffers = static_cast<vector<fuse_buf>*>(read_data);

    syslog(LOG_DEBUG, "preparing %zu bytes at offset %"PRId64, length, offset);

    int band_file_fd = sparsebundle_read_buf_prepare_file(band_path);
    if (band_file_fd != -1) {
        struct stat band_stat;
        stat(band_path, &band_stat);
        read += max(off_t(0), min(static_cast<off_t>(length), band_stat.st_size - offset));
    } else if (errno != ENOENT) {
        syslog(LOG_ERR, "failed to open band %s: %s", band_path, strerror(errno));
        return -errno;
    }

    if (read > 0) {
        fuse_buf buffer = { read, fuse_buf_flags(FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK), 0, band_file_fd, offset };
        buffers->push_back(buffer);
    }

    return read;
}

static const char zero_device[] = "/dev/zero";

static int sparsebundle_read_buf_pad_with_zeroes(size_t length, void *read_data)
{
    vector<fuse_buf> *buffers = static_cast<vector<fuse_buf>*>(read_data);
    int zero_device_fd = sparsebundle_read_buf_prepare_file(zero_device);
    fuse_buf buffer = { length, fuse_buf_flags(FUSE_BUF_IS_FD), 0, zero_device_fd, 0 };
    buffers->push_back(buffer);

    return length;
}

static void sparsebundle_read_buf_close_files()
{
    syslog(LOG_DEBUG, "closing %u open file descriptor(s)", SB_DATA->open_files.size());

    map<string, int>::iterator iter;
    for(iter = SB_DATA->open_files.begin(); iter != SB_DATA->open_files.end(); ++iter)
        close(iter->second);

    SB_DATA->open_files.clear();
}

static int sparsebundle_read_buf(const char *path, struct fuse_bufvec **bufp,
                        size_t length, off_t offset, struct fuse_file_info *fi)
{
syslog(LOG_DEBUG, "sparsebundle_read_buf");
    int ret = 0;

    vector<fuse_buf> buffers;

    sparsebundle_read_operations read_ops = {
        &sparsebundle_read_buf_process_band,
        sparsebundle_read_buf_pad_with_zeroes,
        &buffers
    };

    syslog(LOG_DEBUG, "asked to read %zu bytes at offset %"PRId64" using zero-copy read", length, offset);

    static struct rlimit fd_limit = { -1, -1 };
    if (fd_limit.rlim_cur < 0)
        getrlimit(RLIMIT_NOFILE, &fd_limit);

    if (SB_DATA->open_files.size() + 1 >= fd_limit.rlim_cur) {
        syslog(LOG_DEBUG, "hit max number of file descriptors");
        sparsebundle_read_buf_close_files();
    }

    ret = sparsebundle_iterate_bands(path, length, offset, &read_ops);
    if (ret < 0)
        return ret;

    size_t bufvec_size = sizeof(struct fuse_bufvec) + (sizeof(struct fuse_buf) * (buffers.size() - 1));
    struct fuse_bufvec *buffer_vector = static_cast<fuse_bufvec*>(malloc(bufvec_size));
    if (buffer_vector == 0)
        return -ENOMEM;

    buffer_vector->count = buffers.size();
    buffer_vector->idx = 0;
    buffer_vector->off = 0;

    copy(buffers.begin(), buffers.end(), buffer_vector->buf);

    syslog(LOG_DEBUG, "returning %d buffers to fuse", buffer_vector->count);
    *bufp = buffer_vector;

    return ret;
}
#endif

static int sparsebundle_release(const char *path, struct fuse_file_info *fi)
{
syslog(LOG_DEBUG, "sparsebundle_release");

	SB_DATA->times_opened--;
    syslog(LOG_DEBUG, "closed %s, now referenced %"PRId64" times", SB_DATA->path, SB_DATA->times_opened);

    if (SB_DATA->times_opened == 0)
    {
        syslog(LOG_DEBUG, "no more references, cleaning up");

#if FUSE_SUPPORTS_ZERO_COPY
        if (!SB_DATA->open_files.empty())
            sparsebundle_read_buf_close_files();
#endif
    }

    return 0;
}

static int sparsebundle_show_usage(char *program_name)
{
    fprintf(stderr, "usage: %s [-o options] [-s] [-f] [-D] [-h] <sparsebundle> <mountpoint>\n", program_name);
    fprintf(stderr, "       -s single thread\n");
    fprintf(stderr, "       -f foreground\n");
    fprintf(stderr, "       -D debug\n");
    fprintf(stderr, "       -h header only\n");
    fprintf(stderr, "       -P password (never use that for real password, only tests !!\n");
    return 1;
}

enum { SPARSEBUNDLE_OPT_DEBUG, SPARSEBUNDLE_OPT_HEADERONLY, SPARSEBUNDLE_PASSWORD };

static int sparsebundle_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    switch (key) {
    case SPARSEBUNDLE_OPT_DEBUG:
        setlogmask(LOG_UPTO(LOG_DEBUG));
        return 0;
    case SPARSEBUNDLE_OPT_HEADERONLY:
    	SB_DATA_CAST(data)->headeronly = true;
        return 0;
    case SPARSEBUNDLE_PASSWORD:
    	//SB_DATA_CAST(data)->password = "";
        return 0;
    case FUSE_OPT_KEY_NONOPT:
        if (SB_DATA_CAST(data)->path)
            return 1;

        SB_DATA_CAST(data)->path = strdup(arg);
        return 0;
    }

    return 1;
}

static off_t read_size(const string &str)
{
    uintmax_t value = strtoumax(str.c_str(), 0, 10);
    if (errno == ERANGE || value > uintmax_t(numeric_limits<off_t>::max())) {
        fprintf(stderr, "Disk image too large to be mounted (%s bytes)\n", str.c_str());
        exit(EXIT_FAILURE);
    }

    return value;
}

int main(int argc, char **argv)
{
    openlog("sparsebundlefs", LOG_CONS | LOG_PERROR, LOG_USER);
    setlogmask(~(LOG_MASK(LOG_DEBUG)));

    struct sparsebundle_data data = {};
    data.headeronly = false;

    static struct fuse_opt sparsebundle_options[] = {
        FUSE_OPT_KEY("-D", SPARSEBUNDLE_OPT_DEBUG),
		FUSE_OPT_KEY("-h", SPARSEBUNDLE_OPT_HEADERONLY),
		{ "--pass=%s", offsetof(struct sparsebundle_data, password), 1 },
        { 0, 0, 0 } // End of options
    };

    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    fuse_opt_parse(&args, &data, sparsebundle_options, sparsebundle_opt_proc);
    fuse_opt_add_arg(&args, "-oro"); // Force read-only mount

    if (!data.path)
        return sparsebundle_show_usage(argv[0]);

    char *abs_path = realpath(data.path, 0);
    if (!abs_path) {
        perror("Could not resolve absolute path");
        return EXIT_FAILURE;
    }

    free(data.path);
    data.path = abs_path;
    data.blocksize = 512;

    cencrypted_v2_header v2header;

    {
      char token_filename[MAXPATHLEN];
      struct stat st;
    	sprintf(token_filename, "%s/token", data.path);
    	stat(token_filename, &st);
    	if (st.st_size > sizeof(cencrypted_v2_header))
    	{
    		v2_read_token(data.path, &v2header, data.hmacsha1_key, data.aes_key, &data.aes_key_size, data.password); // *****************************

    		HMAC_CTX_init(&data.hmacsha1_ctx);
    		HMAC_Init_ex(&data.hmacsha1_ctx, data.hmacsha1_key, sizeof(data.hmacsha1_key), EVP_sha1(), NULL);
    		AES_set_decrypt_key(data.aes_key, data.aes_key_size * 8, &data.aes_decrypt_key);
    		data.blocksize = v2header.blocksize;
    		data.encrypted = true;
    	}

    }

    char *plist_path;
    if (asprintf(&plist_path, "%s/Info.plist", data.path) == -1) {
        perror("Failed to resolve Info.plist path");
        return EXIT_FAILURE;
    }

    ifstream plist_file(plist_path);
    stringstream plist_data;
    plist_data << plist_file.rdbuf();

    string key, line;
    while (getline(plist_data, line)) {
        static const char whitespace_chars[] = " \n\r\t";
        line.erase(0, line.find_first_not_of(whitespace_chars));
        line.erase(line.find_last_not_of(whitespace_chars) + 1);

        if (line.compare(0, 5, "<key>") == 0) {
            key = line.substr(5, line.length() - 11);
        } else if (!key.empty()) {
            line.erase(0, line.find_first_of('>') + 1);
            line.erase(line.find_first_of('<'));

            if (key == "band-size")
                data.band_size = read_size(line);
            else if (key == "size")
                data.size = read_size(line);

            key.clear();
        }
    }

    if ( data.headeronly ) {
    	char buffer[data.blocksize];
    	uint64_t offset = 1024;
		sparsebundle_read_not_fuse(data.path, buffer, data.blocksize, offset, &data);
		print_hex(buffer, 64, "Block 0");
    	exit(EXIT_SUCCESS);
    }

    syslog(LOG_DEBUG, "initialized %s, band size%"PRId64", total size %"PRId64, data.path, data.band_size, data.size);
    syslog(LOG_DEBUG, "initialized %s, block size %zu", data.path, data.blocksize);
    syslog(LOG_DEBUG, "sizeof(off_t)=%zu", sizeof(off_t));

    struct fuse_operations sparsebundle_filesystem_operations = {};
    sparsebundle_filesystem_operations.getattr = sparsebundle_getattr;
    sparsebundle_filesystem_operations.open = sparsebundle_open;
    if ( data.encrypted ) {
    	sparsebundle_filesystem_operations.read = sparsebundle_read_encrypted;
    }else{
    	sparsebundle_filesystem_operations.read = sparsebundle_read_not_encrypted;
    }
    sparsebundle_filesystem_operations.readdir = sparsebundle_readdir;
    sparsebundle_filesystem_operations.release = sparsebundle_release;
#if FUSE_SUPPORTS_ZERO_COPY
    sparsebundle_filesystem_operations.read_buf = sparsebundle_read_buf;
#endif

    return fuse_main(args.argc, args.argv, &sparsebundle_filesystem_operations, &data);
}
