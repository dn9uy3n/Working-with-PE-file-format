#include <stdio.h>
#include <Windows.h>

int main(int argc, char *argv[]){
	
	HANDLE fi, mapOb;
	DWORD rawOffset, *currThunk;
	LPVOID point, inject;
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS peHeader;
	PIMAGE_FILE_HEADER fileHeader;
	PIMAGE_OPTIONAL_HEADER32 opHeader;
	PIMAGE_SECTION_HEADER secHeader,secCode;
	PIMAGE_DATA_DIRECTORY dataDic;
	PIMAGE_EXPORT_DIRECTORY exp;
	PIMAGE_IMPORT_DESCRIPTOR imp;
	
	if(argc < 2){
		printf("Usage: ./ImpExpPEFile.exe target.exe");
		ExitProcess(0);
	}
	
	//******* input file *******
	// load file
	fi = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fi == INVALID_HANDLE_VALUE){
		printf("\n==> Error: Can't open file!\n'");
	}else{
		
		// maping file to memory
		mapOb = CreateFileMapping(fi, NULL, PAGE_READONLY, 0, 0, NULL);
		point = MapViewOfFile(mapOb, FILE_MAP_READ, 0, 0, 0);
		
		// DOS Header
		dosHeader = (PIMAGE_DOS_HEADER)point;
		
		// PE Header
		peHeader = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);
		
		// File Header
		fileHeader = (PIMAGE_FILE_HEADER)&peHeader->FileHeader;
		
		// check 'MZ' , 'PE'
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			printf("==> Error: Dos Header failse!\n");
		else if(peHeader->Signature != IMAGE_NT_SIGNATURE)
			printf("==> Error: PE Header false!\n");
		else{
		
			// Optional Header
			opHeader = (PIMAGE_OPTIONAL_HEADER32)&peHeader->OptionalHeader;
			
			// Data Directory
			dataDic = opHeader->DataDirectory;
			
			//********** Export Sections ***************
			if( dataDic[0].Size > 0){
				secHeader = IMAGE_FIRST_SECTION(peHeader);
			
				for(int i = 0; i < fileHeader->NumberOfSections; i++){
					if((secHeader->VirtualAddress <= dataDic[0].VirtualAddress) && (secHeader->VirtualAddress + secHeader->Misc.VirtualSize > dataDic[0].VirtualAddress)){
						//printf("1\n");
						break;
	
					}
					
					secHeader++;
				}
				
				rawOffset = (DWORD)point + secHeader->PointerToRawData;
				
				printf("[*] Export Data Section:\n");
				
				exp = (PIMAGE_EXPORT_DIRECTORY)(rawOffset + dataDic[0].VirtualAddress - secHeader->VirtualAddress);
					
				printf("- DLL name: %s\n", rawOffset + exp->Name - secHeader->VirtualAddress);
					
				DWORD *eat = (DWORD*)(rawOffset + exp->AddressOfFunctions - secHeader->VirtualAddress);
				WORD *eot = (WORD*)(rawOffset + exp->AddressOfNameOrdinals - secHeader->VirtualAddress);
				DWORD *ent = (DWORD*)(rawOffset + exp->AddressOfNames - secHeader->VirtualAddress);
					
				for( int i=0; i<exp->NumberOfFunctions; i++){
					printf("\tFuntion RVAs: %#x", eat[i]);
						
					for(int j=0; j<exp->NumberOfNames; j++){
							
						if (i == eot[j]){
							printf("\tName: %s", (rawOffset + ent[j] - secHeader->VirtualAddress));
							break;
						}
					}
						
				printf ("\n");
				}
			}
			
			//******** Import Sections *********
			
			if(dataDic[1].Size > 0){
				secHeader = IMAGE_FIRST_SECTION(peHeader);
			
				for(int i = 0; i < fileHeader->NumberOfSections; i++){
					if((secHeader->VirtualAddress <= dataDic[1].VirtualAddress) && (secHeader->VirtualAddress + secHeader->Misc.VirtualSize > dataDic[1].VirtualAddress)){
						break;
					}
					
					secHeader++;
				}
				
				rawOffset = (DWORD)point + secHeader->PointerToRawData;
				
				printf("----------------------------------------------------------------\n");
				printf("[*] Import Data Section:\n");
				
				imp = (PIMAGE_IMPORT_DESCRIPTOR)( rawOffset + dataDic[1].VirtualAddress - secHeader->VirtualAddress);
					
				while (imp->Characteristics != 0  || imp->FirstThunk != 0 || imp->ForwarderChain != 0 || imp->Name != 0 || imp->OriginalFirstThunk != 0 || imp->TimeDateStamp != 0){
				
					printf("- DLL name: %s\n", rawOffset + imp->Name - secHeader->VirtualAddress);
							
					// check OFT
					if (imp->OriginalFirstThunk != 0){
						currThunk = (DWORD*)(rawOffset + imp->OriginalFirstThunk - secHeader->VirtualAddress);
					}else{
						currThunk = (DWORD*)(rawOffset + imp->FirstThunk - secHeader->VirtualAddress);
					}
		
					while( *currThunk != 0){
								
						DWORD imgTrnkData = *currThunk;
		
						// check ordinal
						if(imgTrnkData & IMAGE_ORDINAL_FLAG32){
							printf("\tOrdinal: %#x\n", imgTrnkData^IMAGE_ORDINAL_FLAG32);
						}else{
							PIMAGE_IMPORT_BY_NAME iibn = (PIMAGE_IMPORT_BY_NAME)(rawOffset + imgTrnkData - secHeader->VirtualAddress);
							printf("\tFuntion: %s\n", iibn->Name);
							
							if()
							
						}
								
						currThunk++;
					}
					imp++;
				}
			}
			
			// ********** find CODE section and adding code to PE file*****************
			secCode = IMAGE_FIRST_SECTION(peHeader);
			
			for(int i = 0; i < fileHeader->NumberOfSections; i++){
				if( i > 0)
					secCode++;
					
				if(secCode->Characteristics == 0x60000020)
					break;
			}
			
			inject = 
		}
		
	}
	
		// close file
	UnmapViewOfFile(point);
	CloseHandle(mapOb);
	CloseHandle(fi);
	
	printf("==> Press any key to exit!");
	getchar();
	return 0;
}
