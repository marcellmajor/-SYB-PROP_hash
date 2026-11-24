#include "syb-prop_repro.h"

unsigned char joke[] = "Q:Whydidtheflydanceonthejar?A:Becausethelidsaidtwisttoopen.HaHa!";

void print_block(unsigned char * bytes, int endpos, const char * szoveg)
{
	printf("\n%s:\n", szoveg);
	for(int i=0;i<endpos;i++)
	{
		if( i % 8 == 0 )
			printf("\n");
		printf("%.2x",bytes[i]);
	}
		printf("\n");
}

void feal_keysch_repro(unsigned char * key)
{
	SetKey( (ByteType*) key);
}

void feal_encrypt_repro(unsigned char * plaintext, unsigned char * ciphertext)
{
	Encrypt( plaintext, ciphertext );
}

void ccat_pad_repro(unsigned char* password, unsigned char* expanded_password)
{
	int i,pwdlen;
	pwdlen = strlen((const char *) password);
	for(i=0;i<pwdlen;i++)
	{
		expanded_password[i] = password[i];
	}
	for(;i<EXPANDED_PWDLEN;i++)expanded_password[i] = 0x1D;
}

void syb_XOR(unsigned char* enc_result, unsigned char* password_block, unsigned char* result)
{
	int i;
	for(i=0; i<8; i++)result[i] = enc_result[i] ^ password_block[i];
}

void syb_apply_salt_byte(unsigned char salt, unsigned char * password, unsigned char * result)
{
	result[0] = salt ^ password[0];
	result[1] = result[0] ^ password[1];
	result[2] = result[1] ^ password[2];
	result[3] = result[1] ^ password[3];
	result[4] = result[1] ^ password[4];
	result[5] = result[1] ^ password[5];
	result[6] = result[1] ^ password[6];
	result[7] = result[1] ^ password[7];
}

/* MSVC CRT rand()/srand() reimplemented explicitly, so results are
 * identical with any standard C compiler and on any platform.
 * (The original PoC relied on the Windows CRT behaviour of rand().)
 * MSVC: state = state * 214013 + 2531011,
 *       rand() = (state >> 16) & 0x7FFF. */
static unsigned int g_seed;

static void syb_srand(unsigned int seed)
{
	g_seed = seed;
}

static int syb_rand(void)
{
	g_seed = g_seed * 0x343FD + 0x269EC3;
	return (int) ((g_seed >> 0x10) & 0x7FFF);
}

unsigned char salt()
{
	unsigned int random = syb_rand();
	random = random >> 8;
	random = random % 0xFF;
	return (unsigned char) random;
}

void meta_keysch_repro(unsigned int seed, unsigned char * password, unsigned char * result)
{
	unsigned char expanded_password[EXPANDED_PWDLEN];
	unsigned char salt_byte;
	unsigned char act_FEAL_key[8];
	unsigned char act_XOR_result[8];
	unsigned int start_pos, block_counter;

	ccat_pad_repro(password,expanded_password);

	salt_byte = salt();
	syb_apply_salt_byte(salt_byte, expanded_password, act_FEAL_key);
	feal_keysch_repro(act_FEAL_key);
	start_pos = seed % 0x30;
	feal_encrypt_repro( (joke + start_pos), result);

	syb_XOR(result, (expanded_password + 1), act_XOR_result);

	salt_byte = salt();
	syb_apply_salt_byte(salt_byte, act_XOR_result, act_FEAL_key);
	feal_keysch_repro(act_FEAL_key);
	start_pos = seed % 0x30;
	feal_encrypt_repro( (joke + start_pos + 1), (result + 8));
	for(block_counter = 2; block_counter<8; block_counter++)
	{
		syb_XOR(result + 8 * (block_counter - 1), (expanded_password + (block_counter * 8) - 7), act_XOR_result);

		salt_byte = salt();

		syb_apply_salt_byte(salt_byte, act_XOR_result, result + block_counter * 8);
	}
}

void meta_encrypt_repro(unsigned char * meta_keysched, unsigned char * result)
{
	unsigned char act_XOR_copy_result[8];
	unsigned int i/*,j*/;

	feal_keysch_repro(meta_keysched);
	feal_encrypt_repro(joke, result);
	for(i=1; i<8; i++)
	{
		feal_keysch_repro(meta_keysched + 8 * i);

		syb_XOR(joke + 8 * i, result + 8 * (i - 1), act_XOR_copy_result);

		feal_encrypt_repro(act_XOR_copy_result, (result + 8 * i));
	}
}

void generate_hash(unsigned char * password, unsigned char seed, unsigned char * result_hash)
{
	unsigned char meta_keysch_result[META_KEYSCH_LEN];
	unsigned char meta_encrypt_result[META_KEYSCH_LEN];

	syb_srand(seed);
	meta_keysch_repro(seed, password, meta_keysch_result);
	meta_encrypt_repro(meta_keysch_result, meta_encrypt_result);
	memcpy(result_hash, meta_encrypt_result + META_KEYSCH_LEN - HASH_LEN, HASH_LEN);
}