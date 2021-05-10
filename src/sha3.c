#include "../include/sha3.h"
#include <string.h>
#include <stdlib.h>

enum {
	SHA3_ByteStream_t,
	SHA3_WordStream_t,
	SHA3_State
} DelIndexes;

void (*SHA3_DEL[])(void *) = {
	(void (*)(void *)) DelByteStream,
	(void (*)(void *)) DelWordStream,
	(void (*)(void *)) DelState
};

ByteStream_t * ByteStream(int len) {
	ByteStream_t *bytes = (ByteStream_t *) malloc(sizeof(ByteStream_t));

	bytes->len = len;
	bytes->bytes = (Byte_t *) calloc(len, sizeof(Byte_t));

	return bytes;
}
ByteStream_t * ByteJoin(ByteStream_t *a, ByteStream_t *b) {
	int len = a->len + b->len;
	ByteStream_t *ab = ByteStream(len);
	memcpy(ab->bytes, a->bytes, a->len);
	memcpy(ab->bytes + a->len, b->bytes, b->len);
	return ab;
}

ByteStream_t * ByteAdd(ByteStream_t *a, Byte_t byte) {
	ByteStream_t *aplus = ByteStream(a->len + 1);
	memcpy(aplus->bytes, a->bytes, a->len);
	aplus->bytes[a->len] = byte;
	return aplus;
}

WordStream_t * WordStream(int len) {
	WordStream_t *wordss = (WordStream_t *) malloc(sizeof(WordStream_t));

	wordss->len = len;
	wordss->words = (Word_t *) calloc(len, sizeof(Word_t));

	return wordss;
}

Word_t ** CreateState() {
	Word_t **state = (Word_t **) malloc(5 * sizeof(Word_t *));
	for (int i = 0; i < 5; i++)
		state[i] = (Word_t *) calloc(5, sizeof(Word_t));
	return state;
}

void Keccak_f(Word_t **a) {
    Word_t RC[] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
	};

    for (int r = 0; r < SHA3_rounds; r++) {
		Word_t *C = (Word_t *) calloc(5, sizeof(Word_t));
		Word_t *D = (Word_t *) calloc(5, sizeof(Word_t));

		for (int x = 0; x < 5; x++) {
            C[x] = a[x][0];
            for (int y = 1; y < 5; y++)
                C[x] ^= a[x][y];
		}
		for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ ROT64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 5; y++)
                a[x][y] ^= D[x];
		}

        int x = 1, y = 0;
		Word_t current = a[x][y];
		for (int t = 0; t < 24; t++) {
            int X = y, Y = (2 * x + 3 * y) % 5;
            Word_t tmp = a[X][Y];
            a[X][Y] = ROT64(current, ((t + 1) * (t + 2) / 2) % 64);
            current = tmp;
            x = X, y = Y;
		}

		for (int y = 0; y < 5; y++) {
            memset(C, 0, 5 * sizeof(Word_t));
			for (int x = 0; x < 5; x++)
                C[x] = a[x][y];
			for (int x = 0; x < 5; x++)
                a[x][y] = (C[x] ^ ((~C[(x + 1) % 5]) & C[(x + 2) % 5]));
		}

        a[0][0] ^= RC[r];

		free(C); free(D);
	}
}

ByteStream_t * Sha3(ByteStream_t *msg, int length) {
	const int
		c = length * 2,
		r = SHA3_b - c,
		q = (r / 8) - msg->len % (r / 8),
		w = 64,
		blocksize = r / w * 8;

	Word_t **state = CreateState();

	ByteStream_t *aux = msg, *aux2;
	if (q == 1) {
		msg = ByteAdd(msg, 0x86); free(aux);
	} else {
		msg = ByteAdd(msg, 0x06);
		Del(aux, ByteStream_t), aux = msg;
		msg = ByteJoin(msg, (aux2 = ByteStream(q - 2)));
		Del(aux, ByteStream_t), Del(aux2, ByteStream_t), aux = msg;
		msg = ByteAdd(msg, 0x80);
		Del(aux, ByteStream_t);
	}

	for (int i = 0; i < msg->len; i += blocksize) {
		for (int j = 0; j < r / w; j++) {
			Word_t i64 = 0x00;
			for (int k = 0; k < 8; k++)
				i64 += (((Word_t) msg->bytes[i + j * 8 + k]) << (8 * k));

			int x = j % 5, y = j / 5;
			state[x][y] ^= i64;
		}
		Keccak_f(state);
	}

	ByteStream_t *hash = ByteStream(length / 8);
	int filled = 0;
	for (int y = 0; y < 5; y++) {
		for (int x = 0; x < 5; x++) {
			int fill =
				sizeof(Word_t) > hash->len - filled ?
				hash->len - filled :
				sizeof(Word_t);
			memcpy(
				hash->bytes + filled,
				&state[x][y],
				fill
				);
			filled += fill;
		}
	}

	Del(state, State);
	return hash;
}

void DelByteStream(ByteStream_t *bytes) {
	free(bytes->bytes);
	free(bytes);
}
void DelWordStream(WordStream_t *words) {
	free(words->words);
	free(words);
}
void DelState(WordStream_t **state) {
	for (int i = 0; i < 5; i++)
		free(state[i]);
	free(state);
}
