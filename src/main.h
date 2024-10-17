#ifndef __MAIN_H
#define __MAIN_H

#define MAX_FILENAME_LEN 256

#define ROTL(a, b)	 (((a) << (b)) | ((a) >> (32 - (b))))

#define QR(a, b, c, d)                                                                     \
	(a += b, d ^= a, d = ROTL(d, 16), c += d, b ^= c, b = ROTL(b, 12), a += b, d ^= a, \
	 d = ROTL(d, 8), c += d, b ^= c, b = ROTL(b, 7))

#define ROUNDS		    20
#define CHACHA20_BLOCK_SIZE 64

#define min(a, b)	    ((a) < (b) ? (a) : (b))

#endif
