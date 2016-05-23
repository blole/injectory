#include "injectory/process.hpp"
#include "injectory/module.hpp"
#include "injectory/library.hpp"
#include "injectory/file.hpp"
#include "injectory/memoryarea.hpp"

#include <stdio.h>
#include <Psapi.h>
#include <boost/filesystem.hpp>
#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>


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

void Process::fixIAT(PBYTE imageBase, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_IMPORT_DESCRIPTOR pImgImpDesc)
{
	fs::path parentPath = path().parent_path();
	if (!SetDllDirectoryW(parentPath.wstring().c_str()))
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_fix_iat() << e_api_function("SetDllDirectory") << e_text("could not set path to target process") << e_file(parentPath) << e_last_error(errcode));
	}

	while (LPSTR lpModuleName = (LPSTR)GetPtrFromRVA(pImgImpDesc->Name, pNtHeader, imageBase))
	{
		// ACHTUNG: LoadLibraryEx kann eine DLL nur anhand des Namen aus einem anderen
		// Verzeichnis laden wie der Zielprozess!
		Module localModule = Module::load(to_wstring(lpModuleName), DONT_RESOLVE_DLL_REFERENCES);

		Library lib(localModule.path());
		Module remoteModule = isInjected(lib);
		if (!remoteModule)
			remoteModule = inject(lib);

		PIMAGE_THUNK_DATA itd = (PIMAGE_THUNK_DATA)GetPtrFromRVA(pImgImpDesc->FirstThunk, pNtHeader, imageBase);

		while(itd->u1.AddressOfData)
		{
			IMAGE_IMPORT_BY_NAME *iibn =
				(PIMAGE_IMPORT_BY_NAME)GetPtrFromRVA(itd->u1.AddressOfData, pNtHeader, imageBase);
			itd->u1.Function = (DWORD_PTR)remoteModule.getProcAddress((LPCSTR)iibn->Name);

			itd++;
		}      

		pImgImpDesc++;
	}
}

void Process::mapSections(void* lpModuleBase, byte* dllBin, PIMAGE_NT_HEADERS nt_header)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);

	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section++)
	{
		void* dst = (void*)( (DWORD_PTR)lpModuleBase + section->VirtualAddress );
		const void* src = (const void*)( (DWORD_PTR)dllBin + section->PointerToRawData );

		memory(dst, section->SizeOfRawData).write(src);

		/*
		// next section header, calculate virtualSize of section header
		SIZE_T virtualSize = section->VirtualAddress;
		//printf("section: %s | %p | %x\n", section->Name, section->VirtualAddress, virtualSize);
		if (section->VirtualAddress)
			virtualSize = section->VirtualAddress - virtualSize;
		PDWORD lpflOldProtect = 0;
		if(!VirtualProtectEx(hProcess, (LPVOID)( (DWORD_PTR)lpModuleBase + section->VirtualAddress ), virtualSize,
			section->Characteristics & 0x00FFFFFF, lpflOldProtect))
		{
			PRINT_ERROR_MSGA("VirtualProtectEx failed.");
			return FALSE;
		}
		*/
	}
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
	//SIZE_T relocationSize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
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

void Process::callTlsInitializers(
	HMODULE hModule,
	DWORD fdwReason,
	PIMAGE_TLS_DIRECTORY pImgTlsDir)
{
	DWORD_PTR pCallbacks = (DWORD_PTR)pImgTlsDir->AddressOfCallBacks;

	if (pCallbacks)
	{
		for (;;)
		{
			void* callback = memory<void*>((void*)pCallbacks);

			if (!callback)
				break;

			remoteDllMainCall(callback, hModule, fdwReason, nullptr);
			pCallbacks += sizeof(DWORD_PTR);
		}
	}
}

void Process::mapRemoteModule(const Library& lib, const bool& verbose)
{
	PIMAGE_BASE_RELOCATION pImgBaseReloc = 0;
	PIMAGE_TLS_DIRECTORY pImgTlsDir = 0;

	try
	{
		namespace ip = boost::interprocess;

		File file = File::create(lib.path(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL);

		ip::file_mapping m_file(lib.path().string().c_str(), ip::read_only);
		ip::mapped_region region(m_file, ip::read_only);

		const IMAGE_DOS_HEADER& dos_header = *(IMAGE_DOS_HEADER*)region.get_address();
		
		if(dos_header.e_magic != IMAGE_DOS_SIGNATURE)
			BOOST_THROW_EXCEPTION (ex_map_remote() << e_text("invalid DOS header"));
		
		IMAGE_NT_HEADERS& nt_header = *(IMAGE_NT_HEADERS*)((DWORD_PTR) region.get_address()+dos_header.e_lfanew);

		if(nt_header.Signature != IMAGE_NT_SIGNATURE)
			BOOST_THROW_EXCEPTION (ex_map_remote() << e_text("invalid PE header"));

		// Allocate space for the module in the remote process
		MemoryArea moduleBase = alloc(nt_header.OptionalHeader.SizeOfImage, false);
		
		// fix imports
		IMAGE_IMPORT_DESCRIPTOR* pImgImpDesc = (IMAGE_IMPORT_DESCRIPTOR*)GetPtrFromRVA(
			nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
			&nt_header,
			(PBYTE)region.get_address());
		if (nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
			fixIAT((PBYTE)region.get_address(), &nt_header, pImgImpDesc);
		
		// fix relocs
		pImgBaseReloc = (PIMAGE_BASE_RELOCATION)GetPtrFromRVA(
			(DWORD)(nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
			&nt_header,
			(BYTE*)region.get_address());
		if(nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			if(!FixRelocations((BYTE*)region.get_address(), moduleBase.address(), &nt_header, pImgBaseReloc))
				BOOST_THROW_EXCEPTION (ex_map_remote() << e_text("error fixing relocations"));
		}

		// Write the PE header into the remote process's memory space
		moduleBase.write(region.get_address(), nt_header.FileHeader.SizeOfOptionalHeader +
			sizeof(nt_header.FileHeader) +
			sizeof(nt_header.Signature));

		// Map the sections into the remote process(they need to be aligned
		// along their virtual addresses)
		mapSections(moduleBase.address(), (byte*)region.get_address(), &nt_header);

		// call all tls callbacks
		//
		pImgTlsDir = (PIMAGE_TLS_DIRECTORY)GetPtrFromRVA(
			nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,
			&nt_header,
			(BYTE*)region.get_address());
		if(nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
			callTlsInitializers((HMODULE)moduleBase.address(), DLL_PROCESS_ATTACH, pImgTlsDir);

		// call entry point
		remoteDllMainCall(
			(LPVOID)((DWORD_PTR)moduleBase.address() + nt_header.OptionalHeader.AddressOfEntryPoint),
			(HMODULE)moduleBase.address(), 1, nullptr);

		if (verbose)
		{
			wprintf(
				L"Successfully injected (%s | PID: %d):\n\n"
				L"  AllocationBase: 0x%p\n"
				L"  EntryPoint:     0x%p\n"
				L"  SizeOfImage:      %.1f kB\n"
				L"  CheckSum:       0x%08x\n",
				lib.path().c_str(),
				id(),
				moduleBase.address(),
				(LPVOID)((DWORD_PTR)moduleBase.address() + nt_header.OptionalHeader.AddressOfEntryPoint),
				nt_header.OptionalHeader.SizeOfImage / 1024.0,
				nt_header.OptionalHeader.CheckSum);
		}
	}
	catch (const boost::exception& e)
	{
		e << e_text("failed to map PE file into memory") << e_library(lib.path()) << e_process(*this);
		throw;
	}
}
