#include <stdio.h>
#include "feal8.h"
#include "syb-prop_repro.h"

#define ITERATIONS 1
#define BLOCK_SIZE 8

unsigned char testkey[] = "\xAD\x4C\x9A\xAD\x87\x36\x01\xCA\xAD\x4C\x9A\xAD\x87\x36\x01\xCA";
unsigned char plaintext[] = "\x51\x3A\x57\x68\x79\x64\x69\x64";
//unsigned char testkey[] = "\xAD\x4C\x9A\xAD\x87\x36\x01\xCA";
//unsigned char testkey[] = "\x4C\xAD\xAD\x9A\x36\x87\xCA\x01";
//unsigned char plaintext[] = "\x68\x57\x3A\x51\x64\x69\x64\x79";
unsigned char deciphered[BLOCK_SIZE];
unsigned char key_schedule[32];
//unsigned char expected_result[] = "\xCE\x79\xEF\x64\x2A\xA5\xBF\x52";

extern HalfWord K89, K1011, K1213, K1415 ;
extern QuarterWord K[16] ;

int main(void)
{
    unsigned char ciphertext[BLOCK_SIZE];
    unsigned char hash_blocks[BLOCK_SIZE*8];
    int i,j;
    //__int64 freq, tStart, tStop;
    //unsigned long TimeDiff;

    //printf("\nplaintext: ");
    //for(i=0;i<BLOCK_SIZE;i++)
    //printf("%.2x",plaintext[i]);
    //QueryPerformanceFrequency((LARGE_INTEGER*)&freq);
    //QueryPerformanceCounter((LARGE_INTEGER*)&tStart);
    for(j=0;j<ITERATIONS;j++)
    {
        SetKey( (ByteType*) testkey);
        Encrypt( plaintext, ciphertext );
    }
    //QueryPerformanceCounter((LARGE_INTEGER*)&tStop);
    //TimeDiff = (unsigned long)(((tStop - tStart) * 1000000) / freq);
    //printf("\nkeysched: ");
    //printf("%.4x %.4x %.4x %.4x\n",K89,K1011,K1213,K1415);
    //for(i=0;i<16;i++)
    //printf("%.4x",K[i]);
    //printf("\nkeysched2:\n");
    //for(i=0;i<32;i++)
    //printf("%.2x", *((( unsigned char* )K) + i) );
    //printf("\ncipher: ");
    //for(i=0;i<BLOCK_SIZE;i++)
    //printf("%.2x",ciphertext[i]);

    //printf("\ndeciphered: ");
    //Decrypt( ciphertext, deciphered );
    //for(i=0;i<BLOCK_SIZE;i++)
    //printf("%.2x",deciphered[i]);

    //printf("\nExecution time: %dms\n",TimeDiff);
    //printf("\nExpected: ");
    //for(i=0;i<BLOCK_SIZE;i++)
    //printf("%.2x",expected_result[i]);
    //printf("\n\n");
    int salt=0xD4;
    generate_hash((unsigned char *) "almafa4", salt, hash_blocks);
    print_block(hash_blocks , HASH_LEN, "hash");

    printf("\n\nResult:\n0x%.2x05",salt);
    for(i=0;i<HASH_LEN;i++)
    printf("%.2x",hash_blocks[i]);
    printf("\n\n");
    return 0;
}
