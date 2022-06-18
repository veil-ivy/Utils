#include <Windows.h>
#include <stdio.h>
#include "Error.h"
#include "Memory.h"
#include "Crypto.h"

typedef enum dwPEOptions {
	READ_IMAGE=-1,
	WRITE_IMAGE=-2
};
typedef enum image_offset {
	END_TEXT=-1
};
typedef enum patch_img_config {
	PATCH_IMAGE_SIZE=1,
	PATCH_IMAGE_OFFSET=2

};
typedef enum add_size {
	CRYPTED_IMAGE_SIZE=1,

};
typedef enum mem_to_copy {
	DEFAULT=0,
	CRYPTED_IMAGE = 1,
};

class PE:private Crypt {
private:
	LPVOID temp = NULL;
	PBYTE rd_image = NULL;
	DWORD fsize = 0;
	HANDLE h_rdwr_image = NULL;
	PIMAGE_DOS_HEADER rd_dos_header = NULL;
	PIMAGE_NT_HEADERS rd_nt_header = NULL;
	PIMAGE_SECTION_HEADER rd_section = NULL;
	LPVOID temp_crypt = NULL;
	DWORD dwtemp = 0;
	DWORD wr_image_size=0;
	DWORD scan_size = 0;
	LPVOID crypted_image = NULL;
	DWORD crypted_size = 0;
	DWORD new_pe_size = 0;
public:
	PE_error append_pe();
	PE_error set_image_config();
	PE_error patch_image(char*section, DWORD offset_to_patch, DWORD patch);
	PE_error crypt_image( CryptImageOptions crypt[],enum dwPEOptions, CryptoOptions Cryptopt[]); //no need for dwPEOptions
	PE_error rdwr_image(char*, DWORD, enum dwPEOptions);
	PE_error map_rdimage();
	PE_error copy_to_memory(enum add_size size,enum mem_to_copy mem);
	PE_error patch_image_config(DWORD to_patch, enum patch_img_config img_config);
	PE_error dump_image(char*dump_path);
protected:
	
	PIMAGE_DOS_HEADER temp_dos_head=NULL;
	PIMAGE_NT_HEADERS temp_nt_head = NULL;
	PIMAGE_SECTION_HEADER temp_section_head = NULL;
	PBYTE wr_image = NULL;
	DWORD image_size = 0;
	PBYTE image = NULL;
};