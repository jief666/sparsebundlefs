#define _FILE_OFFSET_BITS 64

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

#include "sparsebundleutil.h"

void print_hex(void *data, uint32_t len, const char* format, ...)
{
	uint32_t ctr;

	if (len > 64) {
		len = 64;
	}

	char buf[len*2+1];
	bzero(buf, sizeof(buf));
	for(ctr = 0; ctr < len; ctr++) {
		sprintf(buf + (ctr*2), "%02x", ((uint8_t *)data)[ctr]);
	}
	{
		char message[2000];
		va_list args;
		va_start(args, format);
		vsnprintf(message, sizeof(message), format, args);
		va_end(args);
		syslog(LOG_DEBUG, "%s : %s", message, buf);
	}
}

void convert_hex(char *str, uint8_t *bytes, int maxlen)
{
	int slen = strlen(str);
	int bytelen = (slen+1)/2;
	int rpos, wpos = 0;

	while(wpos < maxlen - bytelen) bytes[wpos++] = 0;

	for(rpos = 0; rpos < bytelen; rpos++) {
		sscanf(&str[rpos*2], "%02hhx", &bytes[wpos++]);
	}
}
