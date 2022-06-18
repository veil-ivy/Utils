#include "Crypto.h"

Crypto_Error Crypt::CryptoHashCryptRC4(CryptoOptions crypto_opt, LPVOID buffer) {	
	RC4Init(crypto_opt.key, strlen((const char *)crypto_opt.key));
	RC4Encrypt((BYTE *)buffer,crypto_opt.size);
		
	return Crypto_Success;
}

Crypto_Error Crypt::CryptoHashCryptRC5(CryptoOptions crypto_opt, LPVOID buffer) {

	return Crypto_Success;		
}
Crypto_Error Crypt::CryptoHashCryptRC6(CryptoOptions crypto_opt, LPVOID buffer) {

	return Crypto_Success;
}
Crypto_Error Crypt::MSCrypt(CryptImageOptions crypt, CryptoOptions crypto_opt) {
	return Crypto_Success;
}

