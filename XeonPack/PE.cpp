#include "PE.h"
//add pe_get_config to get current pe to work over....
//add pe_remap and reposition temp headers...

PE_error PE::dump_image(char*dump_path) {
	//add options to dump PE
	
	wr_image = image;
	rdwr_image(dump_path, new_pe_size,WRITE_IMAGE );
	return PE_error_success;

}
PE_error PE::append_pe() {
				//for now crypted PE......

	dwtemp = 0;
	temp_dos_head = (PIMAGE_DOS_HEADER)image;
	temp_nt_head = (PIMAGE_NT_HEADERS)((PBYTE)image + temp_dos_head->e_lfanew);
	temp_section_head = IMAGE_FIRST_SECTION(temp_nt_head);
	
	rd_dos_header = (PIMAGE_DOS_HEADER)rd_image;
	rd_nt_header = (PIMAGE_NT_HEADERS)((PBYTE)image + temp_dos_head->e_lfanew);
	rd_section = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(temp_nt_head);
	
	
	CopyMemory(&image[fsize], crypted_image, crypted_size);
	/*temp_section_head->SizeOfRawData = ALIGN_UP(temp_section_head->Misc.VirtualSize + crypted_size, temp_nt_head->OptionalHeader.FileAlignment);
	temp_section_head->Misc.VirtualSize += crypted_size;
	dwtemp = fsize;
	
	dwtemp -= rd_section->SizeOfRawData;
	*/
	/*CopyMemory(&image[temp_section_head->PointerToRawData + temp_section_head->Misc.VirtualSize],(PBYTE)&rd_image[rd_section->PointerToRawData + rd_section->Misc.VirtualSize],dwtemp );
	*/
	new_pe_size = fsize + crypted_size + 1;

	return PE_error_success;



}
PE_error PE::patch_image_config(DWORD to_patch,enum patch_img_config img_config) {
	dwtemp = 0;
	temp_dos_head = (PIMAGE_DOS_HEADER)image;
	temp_nt_head = (PIMAGE_NT_HEADERS)((PBYTE)image + temp_dos_head->e_lfanew);
	temp_section_head = IMAGE_FIRST_SECTION(temp_nt_head);
	
	switch (img_config) {
	case PATCH_IMAGE_OFFSET: {
		//cmp end  section name
		dwtemp = fsize;
		patch_image((char*)".text", to_patch, dwtemp);
		break;
 
	}
	case PATCH_IMAGE_SIZE: {
		//image size or size on disk ?
		dwtemp = crypted_size;
			
		patch_image((char*)".text", to_patch, dwtemp);
		break;
	}
	default:
		break;
	}
	return PE_error_success;
}
PE_error PE::patch_image( char *section, DWORD offset_to_patch, DWORD patch) {
	dwtemp = 0;

	temp_dos_head = (PIMAGE_DOS_HEADER)image;
	temp_nt_head = (PIMAGE_NT_HEADERS)((PBYTE)image + temp_dos_head->e_lfanew);
	temp_section_head = IMAGE_FIRST_SECTION(temp_nt_head);
	if (memcmp(temp_section_head->Name, section, strlen(section))!=0)
		return PE_error_success; //change this
	
	for (int i = 0; i < image_size ; i++) {
		if (*(DWORD*)(&image[i]) == offset_to_patch) {
			*(DWORD*)(&image[i]) = patch;
		}
	}
	
	return PE_error_success;

}


//configuration:
//image_size
PE_error PE::set_image_config() {//by setting image config we can choose wether enum in image size patch or according to configuration...
	
	return PE_error_success;
}

PE_error PE::crypt_image(CryptImageOptions crypt[], enum dwPEOptions peoptions, CryptoOptions CryptOptions[]) {
	dwtemp = 0;
	if (peoptions == WRITE_IMAGE)
		temp_crypt = wr_image;
	else if (peoptions == READ_IMAGE)
		temp_crypt = rd_image;
	crypted_image = temp_crypt;
	if (image_size == 0)
		crypted_size = fsize;
	else
		crypted_size = image_size;
	while (crypt[dwtemp] != CRYPT_OPTION_END) {
		if (image_size == 0)
			CryptOptions[dwtemp].size = fsize;
		else
			CryptOptions[dwtemp].size = image_size;
		
		switch (crypt[dwtemp]) {
			case CRYPTO_HASH_RC4: {
				Crypt::CryptoHashCryptRC4(CryptOptions[dwtemp], temp_crypt);
				break;
			}
			case CRYPTO_HASH_RC5: {
				
				Crypt::CryptoHashCryptRC5(CryptOptions[dwtemp], temp_crypt);
				break;
			}
			case CRYPTO_HASH_RC6: {
				Crypt::CryptoHashCryptRC6(CryptOptions[dwtemp], temp_crypt);
				break;
			}
			
			}
		dwtemp++;
		}
		
	return PE_error_success;

}
PE_error PE::copy_to_memory(enum add_size size,enum mem_to_copy mem) {
	dwtemp = 0;
	temp = NULL;
	switch (size) {
	case CRYPTED_IMAGE_SIZE: {
		dwtemp = image_size + crypted_size + 0x1000;
		
		break;
	}
	default:
		dwtemp = image_size + 1;
	}
	image = (PBYTE)MemAlloc(dwtemp); //change it to heap alloc becuase we have heaprealloc 
	ZeroMemory(image, dwtemp);
	dwtemp = 0;
	temp = NULL;
	switch (mem) {
	case CRYPTED_IMAGE: {
		temp = crypted_image;
		dwtemp = crypted_size;
	}
	default:
		temp = rd_image;
		dwtemp = image_size; //will this work ?
	}

	CopyMemory(image, rd_image, dwtemp);
	
	return PE_error_success;

}

PE_error PE::map_rdimage() {
	if (rd_image == NULL)
		return rdwr_map_failed;
	rd_dos_header = (PIMAGE_DOS_HEADER)rd_image;
	rd_nt_header = (PIMAGE_NT_HEADERS)((PBYTE)rd_image + rd_dos_header->e_lfanew); 
	image_size = rd_nt_header->OptionalHeader.SizeOfImage;
	return PE_error_success;

} 
//how about using std::vector to push all opened file buffers ?
PE_error PE::rdwr_image(char* rdwr_file, DWORD rdwrbyte, enum dwPEOptions pe_options) {
	switch (pe_options) {
	case READ_IMAGE: {
		h_rdwr_image = CreateFile(rdwr_file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!h_rdwr_image)
			return rdwr_image_failed;
		fsize = GetFileSize(h_rdwr_image, 0);
		if (fsize == 0)
			goto rd_wr_fail;
		rd_image = (PBYTE)MemAlloc(fsize);
		if (!rd_image)
			goto rd_wr_fail;
		if (!ReadFile(h_rdwr_image, rd_image, fsize, 0, 0))
			goto rd_wr_fail;
		CloseHandle(h_rdwr_image);
		return PE_error_success;
	}
	case WRITE_IMAGE: {
		DWORD written = 0;
		h_rdwr_image = CreateFile(rdwr_file, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!h_rdwr_image)
			return rdwr_image_failed;
		if (!WriteFile(h_rdwr_image, wr_image, rdwrbyte, &written, 0))
			goto rd_wr_fail;
		CloseHandle(h_rdwr_image);
		return PE_error_success;

	}
	

	
	}
rd_wr_fail:
	CloseHandle(h_rdwr_image);
	return rdwr_image_failed;


}
