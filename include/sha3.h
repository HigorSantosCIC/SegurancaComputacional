#ifndef __SHA3__
#define __SHA3__

#include <stdint.h>
#include <stdio.h>

#define SHA3_b 1600
#define SHA3_rounds 24

typedef uint8_t Byte_t;
typedef struct {
	Byte_t *bytes;
	int len;
} ByteStream_t;

typedef uint64_t Word_t;
typedef struct {
	Word_t *words;
	int len;
} WordStream_t;

ByteStream_t * ByteStream(int len); 

ByteStream_t * ByteJoin(ByteStream_t *a, ByteStream_t *b);
ByteStream_t * ByteAdd(ByteStream_t *a, Byte_t byte);
#define BytesFromChar(SHA3_Bytes, text) memcpy(SHA3_Bytes->bytes, text, strlen(text))
#define PrintBytes(SHA3_Bytes) { \
	for (int SHA3_Byte_idx = 0; SHA3_Byte_idx < SHA3_Bytes->len; SHA3_Byte_idx++) \
		printf("%02x", SHA3_Bytes->bytes[SHA3_Byte_idx]); \
	printf("\n"); \
} NULL

WordStream_t * WordStream(int len); 
#define WordsFromBytes(words, bytes) memcpy(words->words, bytes->bytes, bytes->len)

Word_t ** CreateState();
#define PrintState(SHA3_State) { \
	for (int i = 0; i < 5; i++) { \
		for (int j = 0; j < 5; j++) \
			printf("%016lx\n", SHA3_State[i][j]); \
		printf("\n"); \
	} \
} NULL

void Keccak_f(Word_t **a);
ByteStream_t * Sha3(ByteStream_t *msg, int length);

#define ROT64(n, d) (n << d | n >> (64 - d))
#define REV64(n) ( \
		n >> 56 & 0xff | \
		n >> 40 & 0xff00 | \
		n >> 24 & 0xff0000 | \
		n >> 8 & 0xff000000 | \
		n << 8 & 0xff00000000 | \
		n << 24 & 0xff0000000000 | \
		n << 40 & 0xff000000000000 | \
		n << 56 & 0xff00000000000000 \
		)

#define Del(x, type) (SHA3_DEL[SHA3_##type])(x)

void DelByteStream(ByteStream_t *bytess);
void DelWordStream(WordStream_t *wordss);
void DelState(WordStream_t **state);

#endif
