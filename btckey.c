#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

static const char* self;
static int testnet;

static BN_CTX* bn;
static EVP_MD_CTX* evp_md;

static void help(void) {
	printf(
		"Usage: %s [options]\n"
		"\n"
		"Generates Bitcoin version 1 addresses.\n"
		"\n"
		"Options:\n"
		"	-t	Generate a testnet address.\n"
		"	-h	Show this help.\n",
		self
	);
}

/* Converts a byte array to the Base58Check representation. */
/* The output buffer is expected to hold at least `size+1` bytes of data. */
static void base58check(const void* data, size_t size, char* buffer) {
	static const char base58check[58] =
		"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	size_t index1, index2;

	/* Initialize BIGNUMs for the division algorithm. */
	BIGNUM* number = BN_bin2bn(data, size, NULL);
	BIGNUM* base = NULL;
	BIGNUM* rem = BN_new();
	BIGNUM* div = BN_new();
	BN_dec2bn(&base, "58");

	/* Convert the number using the static conversion table. */
	index1 = 0;
	do {
		unsigned int value;
		BN_div(div, rem, number, base, bn);
		BN_bn2binpad(rem, (unsigned char*)&value, sizeof value);
		BN_copy(number, div);
		buffer[index1++] = base58check[ntohl(value)];
	}
	while (!BN_is_zero(number));

	/* Append zeroes for every trailing null byte in the data buffer. */
	for (index2 = 0; index2 < size && !((char*)data)[index2]; ++index2)
		buffer[index1++] = base58check[0];

	/* Reverse the string. */
	for (index2 = 0; index2 < index1 >> 1; ++index2) {
		char temp = buffer[index2];
		buffer[index2] = buffer[index1 - index2 - 1];
		buffer[index1 - index2 - 1] = temp;
	}
	buffer[index1] = 0;

	/* Free BIGNUMs. */
	BN_free(number);
	BN_free(base);
	BN_free(rem);
	BN_free(div);
}

int main(int argc, char* argv[]) {
	int option;
	EC_KEY* key;

	self = *argv;
	while ((option = getopt(argc, argv, "ht")) != -1)
		switch (option) {
		case 't':
			testnet = 1;
			break;
		case 'h':
			help();
			return EXIT_SUCCESS;
		default:
			fprintf(stderr, "Run `%s -h' for help.\n", self);
			return EXIT_FAILURE;
		}

	/* Initialize OpenSSL stuff. */
	evp_md = EVP_MD_CTX_new();
	bn = BN_CTX_new();

	/* Generate a new ECDSA secp256k1 key. */
	key = EC_KEY_new_by_curve_name(NID_secp256k1);
	EC_KEY_generate_key(key);

	/* Process private key. */
	{
		unsigned char buffer1[37];
		unsigned char buffer2[52];
		size_t index;

		/* Get private key. */
		EC_KEY_priv2oct(key, buffer1 + 1, 32);

		/* Print private key. */
		for (index = 0; index < 32; ++index)
			printf("%02X", buffer1[index + 1]);
		putchar('\n');

		/* Prepend version prefix. */
		buffer1[0] = !testnet ? 0x80 : 0xEF;

		/* Calculate SHA-256 twice. */
		EVP_DigestInit(evp_md, EVP_sha256());
		EVP_DigestUpdate(evp_md, buffer1, 33);
		EVP_DigestFinal_ex(evp_md, buffer2, NULL);
		EVP_DigestInit(evp_md, EVP_sha256());
		EVP_DigestUpdate(evp_md, buffer2, 32);
		EVP_DigestFinal_ex(evp_md, buffer2, NULL);

		/* Append checksum. */
		memcpy(buffer1 + 33, buffer2, 4);

		/* Convert to Base58Check and print private key in WIF. */
		base58check(buffer1, 37, (char*)buffer2);
		printf("%s\n", buffer2);
	}

	/* Process public key. */
	{
		unsigned char buffer1[65];
		unsigned char buffer2[32];
		size_t index;

		/* Get public key. */
		const EC_GROUP* group = EC_KEY_get0_group(key);
		const EC_POINT* point = EC_KEY_get0_public_key(key);

		/* Get raw public key. */
		EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
			buffer1, 65, bn);

		/* Print uncompressed public key. */
		for (index = 0; index < 65; ++index)
			printf("%02X", buffer1[index]);
		putchar('\n');

		/* Calculate SHA-256. */
		EVP_DigestInit(evp_md, EVP_sha256());
		EVP_DigestUpdate(evp_md, buffer1, 65);
		EVP_DigestFinal_ex(evp_md, buffer2, NULL);

		/* Calculate RIPEMD-160. */
		EVP_DigestInit(evp_md, EVP_ripemd160());
		EVP_DigestUpdate(evp_md, buffer2, 32);
		EVP_DigestFinal_ex(evp_md, buffer2 + 1, NULL);

		/* Print HASH160 of public key. */
		for (index = 0; index < 20; ++index)
			printf("%02X", buffer2[index + 1]);
		putchar('\n');

		/* Prepend version information. */
		buffer2[0] = !testnet ? 0 : 0x6F;

		/* Calculate SHA-256 twice. */
		EVP_DigestInit(evp_md, EVP_sha256());
		EVP_DigestUpdate(evp_md, buffer2, 21);
		EVP_DigestFinal_ex(evp_md, buffer1, NULL);
		EVP_DigestInit(evp_md, EVP_sha256());
		EVP_DigestUpdate(evp_md, buffer1, 32);
		EVP_DigestFinal_ex(evp_md, buffer1, NULL);

		/* Append checksum. */
		memcpy(buffer2 + 21, buffer1, 4);

		/* Convert to Base58Check and print Bitcoin address. */
		base58check(buffer2, 25, (char*)buffer1);
		printf("%s\n", buffer1);
	}

	/* Free OpenSSL stuff. */
	EC_KEY_free(key);
	EVP_MD_CTX_free(evp_md);
	BN_CTX_free(bn);
	return EXIT_SUCCESS;
}
