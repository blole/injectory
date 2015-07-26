////////////////////////////////////////////////////////////////////////////////////////////
// loader: command-line interface dll injector
// Copyright (C) 2009-2011 Wadim E. <wdmegrv@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
////////////////////////////////////////////////////////////////////////////////////////////
#include "manualmap.hpp"

// Matt Pietrek's function
PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD_PTR rva, PIMAGE_NT_HEADERS pNTHeader)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
	WORD nSection = 0;

	for(nSection = 0; nSection < pNTHeader->FileHeader.NumberOfSections; nSection++, section++ )
	{
		// This 3 line idiocy is because Watcom's linker actually sets the
		// Misc.VirtualSize field to 0.  (!!! - Retards....!!!)
		DWORD_PTR size = section->Misc.VirtualSize;
		if(size == 0)
		{
			size = section->SizeOfRawData;
		}

		// Is the RVA within this section?
		if( (rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + size)) )
		{
			return section;
		}
	}

	return 0;
}

// Matt Pietrek's function
LPVOID GetPtrFromRVA(DWORD_PTR rva, PIMAGE_NT_HEADERS pNTHeader, PBYTE imageBase)
{
	PIMAGE_SECTION_HEADER section;
	LONG_PTR delta;

	section = GetEnclosingSectionHeader(rva, pNTHeader);
	if(!section)
	{
		return 0;
	}

	delta = (LONG_PTR)( section->VirtualAddress - section->PointerToRawData );
	return (LPVOID)( imageBase + rva - delta );
}

BOOL
FixIAT(
	DWORD dwProcessId,
	HANDLE hProcess,
	PBYTE imageBase,
	PIMAGE_NT_HEADERS pNtHeader,
	PIMAGE_IMPORT_DESCRIPTOR pImgImpDesc
	)
{
	BOOL bRet = FALSE;
	LPSTR lpModuleName = 0;
	HMODULE hLocalModule = 0;
	HMODULE hRemoteModule = 0;
	WCHAR modulePath[MAX_PATH + 1] = {0};
	WCHAR moduleNtPath[500 + 1] = {0};
	WCHAR targetProcPath[MAX_PATH + 1] = {0};
	WCHAR *pch = 0;

	__try
	{
		//printf("Fixing Imports:\n");

		// get target process path
		if(!GetModuleFileNameExW(hProcess, (HMODULE)0, targetProcPath, MAX_PATH))
		{
			PRINT_ERROR_MSGA("Could not get path to target process.");
			__leave;
		}

		pch = wcsrchr(targetProcPath, '\\');
		if(pch)
		{
			targetProcPath[ pch - targetProcPath + 1 ] = (WCHAR)0;
		}

		if(!SetDllDirectoryW(targetProcPath))
		{
			PRINT_ERROR_MSGW(L"Could not set path to target process (%s).", targetProcPath);
			__leave;
		}

		while((lpModuleName = (LPSTR)GetPtrFromRVA(pImgImpDesc->Name, pNtHeader, imageBase)))
		{
			PIMAGE_THUNK_DATA itd = 0;

			//printf("module: %s\n", lpModuleName);

			// ACHTUNG: LoadLibraryEx kann eine DLL nur anhand des Namen aus einem anderen
			// Verzeichnis laden wie der Zielprozess!
			hLocalModule = LoadLibraryExA(lpModuleName, 0, DONT_RESOLVE_DLL_REFERENCES);
			if(!hLocalModule)
			{
				PRINT_ERROR_MSGA("Could not load module locally.");
				__leave;
			}

			// get full path of module
			if(!GetModuleFileNameW(hLocalModule, modulePath, MAX_PATH))
			{
				PRINT_ERROR_MSGA("Could not get path to module (%s).", lpModuleName);
				__leave;
			}

			// get nt path
			if(!GetFileNameNtW(modulePath, moduleNtPath, 500))
			{
				PRINT_ERROR_MSGA("Could not get the NT namespace path.");
				__leave;
			}

			// Module already in process?
			hRemoteModule = (HMODULE)ModuleInjectedW(hProcess, moduleNtPath);
			if(!hRemoteModule)
			{
				if(!InjectLibraryW(dwProcessId, modulePath))
				{
					PRINT_ERROR_MSGW(L"Could not inject required module (%s).\n", modulePath);
					__leave;
				}
				
				hRemoteModule = (HMODULE)ModuleInjectedW(hProcess, moduleNtPath);
			}

			itd = (PIMAGE_THUNK_DATA)GetPtrFromRVA(pImgImpDesc->FirstThunk, pNtHeader, imageBase);

			while(itd->u1.AddressOfData)
			{
				IMAGE_IMPORT_BY_NAME *iibn =
					(PIMAGE_IMPORT_BY_NAME)GetPtrFromRVA(itd->u1.AddressOfData, pNtHeader, imageBase);
				itd->u1.Function = (DWORD_PTR)GetRemoteProcAddress(hProcess, hRemoteModule, (LPCSTR)iibn->Name);

				//printf("Function: %s\n", (LPCSTR)iibn->Name);

				itd++;
			}      

			pImgImpDesc++;
		}

		bRet = TRUE;
	}
	__finally
	{
		if(hLocalModule)
		{
			FreeLibrary(hLocalModule);
		}
	}

	return bRet;
}

BOOL
MapSections(
	HANDLE hProcess,
	LPVOID lpModuleBase,
	PBYTE dllBin,
	PIMAGE_NT_HEADERS pNTHeader
	)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
	SIZE_T virtualSize = 0;
	WORD nSection = 0;
	
	for(nSection = 0; nSection < pNTHeader->FileHeader.NumberOfSections; nSection++)
	{
		LPVOID lpBaseAddress = (LPVOID)( (DWORD_PTR)lpModuleBase + section->VirtualAddress );
		LPCVOID lpBuffer = (LPCVOID)( (DWORD_PTR)dllBin + section->PointerToRawData );
		SIZE_T NumBytesWritten = 0;
		PDWORD lpflOldProtect = 0;

		if(!WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, section->SizeOfRawData, &NumBytesWritten) ||
			NumBytesWritten != section->SizeOfRawData)
		{
			PRINT_ERROR_MSGA("Could not write to memory in remote process.");
			return FALSE;
		}	
		
		// next section header, calculate virtualSize of section header
		virtualSize = section->VirtualAddress;
		//printf("section: %s | %p | %x\n", section->Name, section->VirtualAddress, virtualSize);
		section++;
		if(section->VirtualAddress)
		{
			virtualSize = section->VirtualAddress - virtualSize;
		}
		/*
		if(!VirtualProtectEx(hProcess, (LPVOID)( (DWORD_PTR)lpModuleBase + section->VirtualAddress ), virtualSize,
			section->Characteristics & 0x00FFFFFF, lpflOldProtect))
		{
			PRINT_ERROR_MSGA("VirtualProtectEx failed.");
			return FALSE;
		}
		*/
	}

	return TRUE;
}

BOOL
FixRelocations(
	PBYTE dllBin,
	LPVOID lpModuleBase,
	PIMAGE_NT_HEADERS pNtHeader,
	PIMAGE_BASE_RELOCATION pImgBaseReloc
	)
{
	LONG_PTR delta = (DWORD_PTR)lpModuleBase - pNtHeader->OptionalHeader.ImageBase;
	SIZE_T relocationSize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	WORD *pRelocData = 0;

	//printf("FixRelocs:\n");

	// image has no relocations
	if(!pImgBaseReloc->SizeOfBlock)
	{
		//printf("Image has no relocations\n");
		return TRUE;
	}
	
	do
	{
		PBYTE pRelocBase = (PBYTE)GetPtrFromRVA(pImgBaseReloc->VirtualAddress, pNtHeader, dllBin);
		SIZE_T numRelocations = (pImgBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		SIZE_T i = 0;

		//printf("numRelocations: %d\n", numRelocations);

		pRelocData = (WORD*)( (DWORD_PTR)pImgBaseReloc + sizeof(IMAGE_BASE_RELOCATION) );

		// loop over all relocation entries
		for(i = 0; i < numRelocations; i++, pRelocData++)
		{
			// Get reloc data
			BYTE RelocType = *pRelocData >> 12;
			WORD Offset = *pRelocData & 0xFFF;

			switch(RelocType)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				break;

			case IMAGE_REL_BASED_HIGHLOW:
				*(DWORD32*)(pRelocBase + Offset) += (DWORD32)delta;
				break;

			case IMAGE_REL_BASED_DIR64:
				*(DWORD64*)(pRelocBase + Offset) += delta;

				break;

			default:
				PRINT_ERROR_MSGA("Unsuppported relocation type.");
				return FALSE;
			}
		}

		pImgBaseReloc = (PIMAGE_BASE_RELOCATION)pRelocData;

	} while( *(DWORD*)pRelocData );

	return TRUE;
}

BOOL
CallTlsInitializers(
	PBYTE imageBase,
	PIMAGE_NT_HEADERS pNtHeader,
	HANDLE hProcess,
	HMODULE hModule,
	DWORD fdwReason,
	PIMAGE_TLS_DIRECTORY pImgTlsDir
	)
{
	DWORD_PTR pCallbacks = (DWORD_PTR)pImgTlsDir->AddressOfCallBacks;

	if(pCallbacks)
	{
		while(TRUE)
		{
			SIZE_T NumBytesRead = 0;
			LPVOID callback = 0;

			if(!ReadProcessMemory(hProcess, (PVOID)pCallbacks, &callback, sizeof(LPVOID), &NumBytesRead) ||
				NumBytesRead != sizeof(LPVOID))
			{
				PRINT_ERROR_MSGA("Could not read memory in remote process.");
				return FALSE;
			}

			if(!callback) break;

			RemoteDllMainCall(hProcess, callback, hModule, fdwReason, 0);
			//printf("callback: %p\n", callback);
			pCallbacks += sizeof(DWORD_PTR);
		}
	}
	return TRUE;
}

BOOL
MapRemoteModuleW(
	DWORD dwProcessId,
	LPCWSTR lpModulePath
	)
{
	BOOL bRet = FALSE;
	HANDLE hFile = 0;
	DWORD fileSize = 0;
	BYTE *dllBin = 0;
	PIMAGE_NT_HEADERS nt_header = 0;
	PIMAGE_DOS_HEADER dos_header = 0;
	HANDLE hProcess = 0;
	LPVOID lpModuleBase = 0;

	PIMAGE_IMPORT_DESCRIPTOR pImgImpDesc = 0;
	PIMAGE_BASE_RELOCATION pImgBaseReloc = 0;
	PIMAGE_TLS_DIRECTORY pImgTlsDir = 0;

	__try
	{
		// Get a handle for the target process.
		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION	|	// Required by Alpha
			PROCESS_CREATE_THREAD		|	// For CreateRemoteThread
			PROCESS_VM_OPERATION		|	// For VirtualAllocEx/VirtualFreeEx
			PROCESS_VM_WRITE			|	// For WriteProcessMemory
			PROCESS_VM_READ,
			FALSE, 
			dwProcessId);
		if(!hProcess)
		{
			PRINT_ERROR_MSGA("Could not get handle to process (PID: 0x%X).", dwProcessId);
			__leave;
		}

		hFile = CreateFileW(
			lpModulePath,
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		if(hFile == INVALID_HANDLE_VALUE)
		{
			PRINT_ERROR_MSGA("CreateFileW failed.");
			__leave;
		}

		if(GetFileAttributesW(lpModulePath) & FILE_ATTRIBUTE_COMPRESSED)
		{
			fileSize = GetCompressedFileSizeW(lpModulePath, NULL);
		}
		else
		{
			fileSize = GetFileSize(hFile, NULL);
		}

		if(fileSize == INVALID_FILE_SIZE)
		{
			PRINT_ERROR_MSGA("Could not get size of file.");
			__leave;
		}

		dllBin = (BYTE*)malloc(fileSize);

		{
			DWORD NumBytesRead = 0;
			if(!ReadFile(hFile, dllBin, fileSize, &NumBytesRead, FALSE))
			{
				PRINT_ERROR_MSGA("ReadFile failed.");
			}
		}
	
		dos_header = (PIMAGE_DOS_HEADER)dllBin;
		
		// Make sure we got a valid DOS header
		if(dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		{
			PRINT_ERROR_MSGA("Invalid DOS header.");
			__leave;
		}
		
		// Get the real PE header from the DOS stub header
		nt_header = (PIMAGE_NT_HEADERS)( (DWORD_PTR)dllBin +
			dos_header->e_lfanew);

		// Verify the PE header
		if(nt_header->Signature != IMAGE_NT_SIGNATURE)
		{
			PRINT_ERROR_MSGA("Invalid PE header.");
			__leave;
		}

		// Allocate space for the module in the remote process
		lpModuleBase = VirtualAllocEx(
			hProcess,
			NULL, 
			nt_header->OptionalHeader.SizeOfImage, 
			MEM_COMMIT | MEM_RESERVE, 
			PAGE_EXECUTE_READWRITE);
		if(!lpModuleBase)
		{
			PRINT_ERROR_MSGA("Could not allocate memory in remote process.");
			__leave;
		}
		
		// fix imports
		pImgImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)GetPtrFromRVA(
			nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
			nt_header,
			(PBYTE)dllBin);
		if(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			if(!FixIAT(dwProcessId, hProcess, (PBYTE)dllBin, nt_header, pImgImpDesc))
			{
				PRINT_ERROR_MSGA("@Fixing imports.");
				__leave;
			}
		}
		
		// fix relocs
		pImgBaseReloc = (PIMAGE_BASE_RELOCATION)GetPtrFromRVA(
			(DWORD)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
			nt_header,
			(PBYTE)dllBin);
		if(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			if(!FixRelocations(dllBin, lpModuleBase, nt_header, pImgBaseReloc))
			{
				PRINT_ERROR_MSGA("@Fixing relocations.");
				__leave;
			}
		}

		// Write the PE header into the remote process's memory space
		{
			SIZE_T NumBytesWritten = 0;
			SIZE_T nSize = nt_header->FileHeader.SizeOfOptionalHeader +
				sizeof(nt_header->FileHeader) +
				sizeof(nt_header->Signature);
			
			if(!WriteProcessMemory(hProcess, lpModuleBase, dllBin, nSize, &NumBytesWritten) ||
				NumBytesWritten != nSize)
			{
				PRINT_ERROR_MSGA("Could not write to memory in remote process.");
				__leave;
			}
		}

		// Map the sections into the remote process(they need to be aligned
		// along their virtual addresses)
		if(!MapSections(hProcess, lpModuleBase, dllBin, nt_header))
		{
			PRINT_ERROR_MSGA("@Map sections.");
			__leave;
		}

		// call all tls callbacks
		//
		pImgTlsDir = (PIMAGE_TLS_DIRECTORY)GetPtrFromRVA(
			nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,
			nt_header,
			(PBYTE)dllBin);
		if(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
		{
			if(!CallTlsInitializers(dllBin, nt_header, hProcess, (HMODULE)lpModuleBase, DLL_PROCESS_ATTACH, pImgTlsDir))
			{
				PRINT_ERROR_MSGA("@Call TLS initializers.");
				__leave;
			}
		}

		// call entry point
		if(!RemoteDllMainCall(
			hProcess,
			(LPVOID)( (DWORD_PTR)lpModuleBase + nt_header->OptionalHeader.AddressOfEntryPoint),
			(HMODULE)lpModuleBase, 1, 0))
		{
			PRINT_ERROR_MSGA("@Call DllMain.");
			__leave;
		}

		bRet = TRUE;

		wprintf(
			L"Successfully injected (%s | PID: %x):\n\n"
			L"  AllocationBase: 0x%p\n"
			L"  EntryPoint:     0x%p\n"
			L"  SizeOfImage:    0x%x\n"
			L"  CheckSum:       0x%x\n",
			lpModulePath,
			dwProcessId,
			lpModuleBase,
			(LPVOID)((DWORD_PTR)lpModuleBase + nt_header->OptionalHeader.AddressOfEntryPoint),
			nt_header->OptionalHeader.SizeOfImage,
			nt_header->OptionalHeader.CheckSum);
	}
	__finally
	{
		if(hFile)
		{
			CloseHandle(hFile);
		}

		if(dllBin)
		{
			free(dllBin);
		}

		if(hProcess)
		{
			CloseHandle(hProcess);
		}
	}
	
	return bRet;
}

BOOL
MapRemoteModuleA(
	DWORD dwProcessId,
	LPCSTR lpModulePath
	)
{
	BOOL bRet = FALSE;
	wchar_t *libpath = char_to_wchar_t(lpModulePath);

	if(libpath == 0)
	{
		return bRet;
	}

	bRet = MapRemoteModuleW(dwProcessId, libpath);

	if(libpath)
	{
		free(libpath);
	}

	return bRet;
}