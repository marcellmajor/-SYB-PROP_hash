/*
Version of 20 September 1989.
*/

typedef unsigned char ByteType ;
//typedef unsigned long HalfWord ;
//typedef unsigned int QuarterWord ;

typedef unsigned int HalfWord ;
typedef unsigned short QuarterWord ;

void SetKey( ByteType * ) ;
void Encrypt( ByteType *Plain, ByteType *Cipher ) ;
void Decrypt( ByteType *Cipher, ByteType *Plain ) ;
