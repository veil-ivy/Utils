#include <Windows.h>
#ifndef CRYPT_H
#define CRYPT_H
#pragma comment(lib,"cryptohash.lib")
#include "cryptohash.h"
#include "Memory.h"
typedef enum dwCryptOptions {
	CRYPT_OPTION_END = 0,
	CRYPTO_HASH_RC4 = 1,
	CRYPTO_HASH_RC5 = 2,
	CRYPTO_HASH_RC6 = 3,



}CryptImageOptions;

typedef struct CryptoOptions {
	BYTE key[100];
	BYTE IV[100];
	DWORD realloc_bytes;
	DWORD size;
}CryptoOptions, * PCryptOptions;
typedef enum Crypto_Error {
	Crypto_Success = 0,
	Crypto_Crypt_Failed = -1
};

class Crypt {

private:
	LPVOID temprealloc_mem = NULL;
	
public:
	Crypto_Error CryptoHashCryptRC4(CryptoOptions crypto_opt,LPVOID buffer);
	Crypto_Error CryptoHashCryptRC5(CryptoOptions crypto_opt, LPVOID buffer);
	Crypto_Error CryptoHashCryptRC6(CryptoOptions crypto_opt, LPVOID buffer);
	Crypto_Error MSCrypt(CryptImageOptions crypt, CryptoOptions crypto_opt);
	


};
#endif