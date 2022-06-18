#include "PE.h"
#include "XeonTemplates.h"

int main() {
	
 	BYTE crypt[100] = "crypt";
	BYTE key[100] = "key";
	RC4Init(key, 100);
	RC4Encrypt((BYTE*)crypt, 100);
	RC4Init(key, 100);
	RC4Decrypt(crypt, 100);
	PE pe;

	CryptImageOptions cryptopt[2] = { CRYPTO_HASH_RC4,CRYPT_OPTION_END };
	pe.rdwr_image((char*)"C:\\folder\\artifact.exe", 0, READ_IMAGE);
	CryptoOptions crypt_opt[2];
	ZeroMemory(crypt_opt[0].key, 100);
	ZeroMemory(crypt_opt[1].key, 100); //add rounds and limits then loop it
	memcpy(crypt_opt[0].key,"key",strlen("key"));
	pe.crypt_image(cryptopt, READ_IMAGE,crypt_opt);   
	pe.rdwr_image((char*)"C:\\Projects\\XeonPack_Section-Template.exe",0,READ_IMAGE);	
	pe.map_rdimage();
	pe.copy_to_memory(CRYPTED_IMAGE_SIZE,DEFAULT); 
	pe.patch_image_config(0xDEADC0DE, PATCH_IMAGE_OFFSET);
	pe.patch_image_config(0xDEADFADE, PATCH_IMAGE_SIZE);
	pe.append_pe();
	pe.dump_image((char*)"C:\\Projects\\dumped.exe");


	/*pe.crypt_image(crypt,)*/
	//
	//DWORD i = 0;
	//BOOL btr = 1 & 0xFFFFFFFF;
	//while (crypt[i]!=CRYPT_OPTION_END ) {
	//	i++;
	//}
}