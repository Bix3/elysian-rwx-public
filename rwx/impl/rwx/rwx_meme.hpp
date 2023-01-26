#pragma once

/*
  mov QWORD PTR [rsp + 8], rcx
  mov DWORD PTR [rsp + 16], edx
  mov DWORD PTR [rsp + 24], r8d
  sub rsp, 32

  mov rax, 0xdeadbeefdeadbeef
  mov QWORD PTR [rsp], rax
  mov rax, 0xdeadbeefdeadbeef
  mov QWORD PTR [rsp + 8], rax

  mov rax, QWORD PTR [rsp]
  mov cl, BYTE PTR [rax + 28]
  test cl, cl
  jnz check_loader
  mov DWORD PTR [rax], 1
  mov BYTE PTR [rax + 28], 1

check_loader:
  mov rax, QWORD PTR [rsp]
  cmp DWORD PTR [rax], 2
  je loader_step
  mov DWORD PTR [rax], 1
  jmp exit_loader

loader_step:
  mov rax, QWORD PTR [rsp]
  mov al, BYTE PTR [rax + 4]
  test al, al
  jz execute_dll
  dec al
  test al, al
  jz terminate_loader
  mov BYTE PTR [rax + 4], 0
  jmp exit_loader

execute_dll:
  mov rax, QWORD PTR [rsp + 24 + 8 + 8]

  mov rcx, QWORD PTR [rsp + 8]
  mov QWORD PTR [rcx], rax
  mov DWORD PTR [rcx + 8], edx
  mov DWORD PTR [rcx + 12], r8d

  mov rax, QWORD PTR [rsp]
  mov edx, DWORD PTR [rax + 24]
  mov r8, QWORD PTR [rax + 16]

  mov rax, QWORD PTR [rax + 8]
  call rax
  mov rcx, QWORD PTR [rsp]
  mov BYTE PTR [rcx + 4], al
  mov rcx, QWORD PTR [rsp + 8]
  mov eax, DWORD PTR [rcx + 16]
  jmp loader_return

terminate_loader:
  mov rax, QWORD PTR [rsp]
  mov DWORD PTR [rax], 0
  xor eax, eax
  add rsp, 32
  ret 0
*/

class handle_meme
{
public:
	_declspec(noinline) auto rva_va( ULONGLONG RVA, PIMAGE_NT_HEADERS nt_header, PVOID LocalImage ) -> PVOID
	{
		VM_DOLPHIN_RED_START

		PIMAGE_SECTION_HEADER pFirstSect = IMAGE_FIRST_SECTION( nt_header );
		for ( PIMAGE_SECTION_HEADER pSection = pFirstSect; pSection < pFirstSect + nt_header->FileHeader.NumberOfSections; pSection++ )
		{
			if ( RVA >= pSection->VirtualAddress && RVA < pSection->VirtualAddress + pSection->Misc.VirtualSize )
			{
				return ( PUCHAR ) LocalImage + pSection->PointerToRawData + (RVA - pSection->VirtualAddress);
			}
		}

		VM_DOLPHIN_RED_END

		return NULL;
	}

	_declspec(noinline) auto TranslateRawSection( PIMAGE_NT_HEADERS nt, DWORD rva ) -> PIMAGE_SECTION_HEADER 
	{
		VM_DOLPHIN_RED_START

		auto section = IMAGE_FIRST_SECTION( nt );
		for ( auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section ) {
			if ( rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize ) {
				return section;
			}
		}

		VM_DOLPHIN_RED_END

		return NULL;
	}

	_declspec(noinline) auto TranslateRaw( PBYTE base, PIMAGE_NT_HEADERS nt, DWORD rva ) -> PVOID
	{
		VM_DOLPHIN_RED_START

		auto section = TranslateRawSection( nt, rva );
		if ( !section ) {
			return NULL;
		}

		VM_DOLPHIN_RED_END

		return base + section->PointerToRawData + (rva - section->VirtualAddress);
	}

	_declspec(noinline) auto resolve_free_function( LPCSTR ModName, LPCSTR ModFunc ) -> ULONGLONG
	{
		VM_DOLPHIN_RED_START;

		HMODULE hModule = LoadLibraryExA( ModName, NULL, DONT_RESOLVE_DLL_REFERENCES );

		ULONGLONG FuncOffset = ( ULONGLONG ) GetProcAddress( hModule, ModFunc );

		FuncOffset -= ( ULONGLONG ) hModule;

		FreeLibrary( hModule );

		VM_DOLPHIN_RED_END;

		return FuncOffset;
	}
public:
	_declspec(noinline) auto relocation (PBYTE pRemoteImg, PBYTE pLocalImg, PIMAGE_NT_HEADERS nt_header) -> bool
	{
		VM_DOLPHIN_RED_START;

		auto& baseRelocDir = nt_header->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
		if ( !baseRelocDir.VirtualAddress ) {
			rwx_log( _( "bad relocation base: 0x%llx\n" ), baseRelocDir );

			return false;
		}

		auto reloc = reinterpret_cast< PIMAGE_BASE_RELOCATION >(TranslateRaw( pLocalImg, nt_header, baseRelocDir.VirtualAddress ));
		if ( !reloc ) {
			rwx_log( _( "bad relocation: 0x%llx\n" ), reloc );

			return false;
		}

		for ( auto currentSize = 0UL; currentSize < baseRelocDir.Size; ) {
			auto relocCount = (reloc->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION )) / sizeof( WORD );
			auto relocData = reinterpret_cast< PWORD >(reinterpret_cast< PBYTE >(reloc) + sizeof( IMAGE_BASE_RELOCATION ));
			auto relocBase = reinterpret_cast< PBYTE >(TranslateRaw( pLocalImg, nt_header, reloc->VirtualAddress ));

			for ( auto i = 0UL; i < relocCount; ++i, ++relocData ) {
				auto data = *relocData;
				auto type = data >> 12;
				auto offset = data & 0xFFF;

				if ( type == IMAGE_REL_BASED_DIR64 ) {
					*reinterpret_cast< PBYTE* >(relocBase + offset) += (pRemoteImg - reinterpret_cast< PBYTE >(nt_header->OptionalHeader.ImageBase));
				}
			}

			currentSize += reloc->SizeOfBlock;
			reloc = reinterpret_cast< PIMAGE_BASE_RELOCATION >(relocData);
		}

		VM_DOLPHIN_RED_END;

		return TRUE;

	}

	_declspec(noinline) auto write_sections( PVOID pModuleBase, PVOID LocalImage, PIMAGE_NT_HEADERS NtHead ) -> bool
	{
		auto section = IMAGE_FIRST_SECTION( NtHead );
		for ( auto i = 0; i < NtHead->FileHeader.NumberOfSections; ++i, ++section ) {
			auto sectionSize = min( section->SizeOfRawData, section->Misc.VirtualSize );
			if ( !sectionSize ) {
				continue;
			}

			auto mappedSection = ( ULONGLONG ) pModuleBase + section->VirtualAddress;
			auto mappedSectionBuffer = ( PVOID ) (( ULONGLONG ) LocalImage + section->PointerToRawData);

			if ( !qtx_device->write_physical_memory( ( const uintptr_t ) mappedSection, mappedSectionBuffer, sectionSize ) ) 
			{
				rwx_log( "failed to map section %s at %p (%x)\n", section->Name, mappedSection, sectionSize );
				return FALSE;
			}
		}

		return true;
	}


	_declspec(noinline) auto imports( PVOID pLocalImg, PIMAGE_NT_HEADERS NtHead ) -> bool
	{
		VM_DOLPHIN_RED_START;

		PIMAGE_IMPORT_DESCRIPTOR ImportDesc = ( PIMAGE_IMPORT_DESCRIPTOR ) rva_va( NtHead->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress, NtHead, pLocalImg );
		
		if ( !NtHead->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress || !NtHead->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size ) \
			return true;

		LPSTR ModuleName = NULL;
		while ( (ModuleName = ( LPSTR ) rva_va( ImportDesc->Name, NtHead, pLocalImg )) ) 
		{
			uintptr_t BaseImage = ( uintptr_t ) LoadLibraryA( ModuleName );

			if ( !BaseImage )
				return false;

			PIMAGE_THUNK_DATA IhData = ( PIMAGE_THUNK_DATA ) rva_va( ImportDesc->FirstThunk, NtHead, pLocalImg );

			while ( IhData->u1.AddressOfData ) 
			{
				if ( IhData->u1.Ordinal & IMAGE_ORDINAL_FLAG )
					IhData->u1.Function = BaseImage + resolve_free_function( ModuleName, ( LPCSTR ) (IhData->u1.Ordinal & 0xFFFF) );

				else 
				{
					IMAGE_IMPORT_BY_NAME* IBN = ( PIMAGE_IMPORT_BY_NAME ) rva_va( IhData->u1.AddressOfData, NtHead, pLocalImg );
					IhData->u1.Function = BaseImage + resolve_free_function( ModuleName, ( LPCSTR ) IBN->Name );
				} IhData++;

			} ImportDesc++;

		} 
		
		VM_DOLPHIN_RED_END;
		return true;
	}

};

class rwx
{
private:
	handle_meme handler;
private:
	_declspec(noinline) auto get_nt_headers( const std::uintptr_t image_base ) -> IMAGE_NT_HEADERS*
	{
		VM_DOLPHIN_RED_START;

		const auto dos_header = reinterpret_cast< IMAGE_DOS_HEADER* > (image_base);

		VM_DOLPHIN_RED_END;

		return reinterpret_cast< IMAGE_NT_HEADERS* > (image_base + dos_header->e_lfanew);
	}

public:
	struct payload_data
	{
		int32_t status;
		uintptr_t dll_main;
		uintptr_t a1;
		uint32_t a2;
		uintptr_t a3;
	};

	typedef struct _remote_dll {
		INT status;
		uintptr_t dll_main_address;
		HINSTANCE dll_base;
	} remote_dll, * premote_dll;

	#define LOADER_STATUS_EXPIRED 0
	#define LOADER_STATUS_WAITING 1
	#define LOADER_STATUS_EXECUTE 2

	uint32_t ldr_data_offset = 6;

	uintptr_t loader_addr, ldr_mdl, ldr_data_ptr, present_address, old_present_ptr;

public:
	_declspec(noinline) qtx::status meme( const int pid, void* buffer, int32_t method )
	{
		VM_TIGER_WHITE_START;

		if ( !buffer )
		{
			rwx_log( _( "invalid dll module\n" ) );

			return qtx::operation_failed;
		}

		VM_TIGER_WHITE_END;

		if ( qtx_device->is_mapped( ) )
		{
			VM_EAGLE_WHITE_START;

			const auto nt_header = get_nt_headers( reinterpret_cast< std::uintptr_t > (buffer) );

			uint8_t remote_loader_shellcode[ ] = { 
				0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x39, 
				0xFF, 0x90, 0x39, 0xC0, 0x90, 0x48, 0x89, 0x44, 
				0x24, 0x20, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x83, 
				0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24, 
				0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 
				0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40, 0x08, 
				0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 
				0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 
				0x24, 0x20, 0x48, 0x8B, 0x48, 0x10, 0xFF, 0x54, 
				0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 
				0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 
				0x38, 0xC3, 0x48, 0x39, 0xC0, 0x90, 0xCC 
			};

			const size_t loader_size = sizeof( remote_loader_shellcode ) + sizeof( payload_data );

			rwx_log( _( "remote_loader_shellcode size: %i.\n" ), loader_size );

			VM_EAGLE_WHITE_END;

			uintptr_t base = 0;
			if ( base = ( uintptr_t ) utl::threads::get_last_thread_stack( pid ) )
			{
				if ( !qtx_device->allocate_memory( base, nt_header->OptionalHeader.SizeOfImage + loader_size ) )
				{
					rwx_log( "unable to allocate memory.\n" );

					return qtx::operation_failed;

				}
				else
					rwx_log( "allocation successful.\n" );
			}


			if ( !base )
			{
				rwx_log( "allocation failed.\n" );

				return qtx::operation_failed;
			}

			VM_EAGLE_WHITE_START;

			rwx_log( _("allocation inserted: 0x%llx.\n"), base );

			if ( !handler.relocation( ( PBYTE ) base, reinterpret_cast< PBYTE > (buffer), nt_header ) )
			{
				qtx_device->free( base );

				rwx_log( _( "image relocation failed: 0x%llx.\n" ), base );

				return qtx::operation_failed;
			}

			if ( !handler.imports( reinterpret_cast< PVOID > (buffer), nt_header ) )
			{
				qtx_device->free( base );

				rwx_log( _( "loading imports failed.\n" ) );

				return qtx::operation_failed;
			}

			if ( !handler.write_sections( ( PVOID ) base, reinterpret_cast< PVOID > (buffer), nt_header ) )
			{
				qtx_device->free( base );

				rwx_log( _( "failed to write section payload.\n" ) );

				return qtx::operation_failed;
			}

			//if ( !handler.discard_sections( ( PVOID ) base, nt_header ) )
			//{
			//	qtx_device->free( base );

			//	rwx_log( _( "failed to discard section payload.\n" ) );

			//	return qtx::operation_failed;
			//}


			ldr_mdl = 0;
			loader_addr = base + nt_header->OptionalHeader.SizeOfImage;

			rwx_log( "shellcode base: 0x%llx.\n", loader_addr );

			//+20 = payload_data
			//movabs rax, ldr_data_ptr
			ldr_data_ptr = loader_addr + sizeof( remote_loader_shellcode );

			memcpy( remote_loader_shellcode + ldr_data_offset, &ldr_data_ptr, sizeof( uintptr_t ) );

			payload_data ldr;
			ldr.status = LOADER_STATUS_EXPIRED;
			ldr.dll_main = ( decltype(ldr.dll_main) ) (base + nt_header->OptionalHeader.AddressOfEntryPoint);
			ldr.a1 = base;
			ldr.a2 = 1;
			ldr.a3 = 0;


			if ( !qtx_device->write_physical_memory( ldr_data_ptr, &ldr, sizeof( ldr ) ) )
			{
				rwx_log( "failed to write payload information to loader memory: 0x%llx.\n", ldr_data_ptr );

				return qtx::operation_failed;
			}

			if ( !qtx_device->write_physical_memory( loader_addr, remote_loader_shellcode, sizeof( remote_loader_shellcode ) ) )
			{
				rwx_log( "failed to write payload into target process 0x%llx.\n", loader_addr );

				return qtx::operation_failed;
			}


			if ( method == 1 )
			{
				const uintptr_t medal_tv = qtx_device->get_module_base( "medal-hook64.dll" );

				rwx_log( "module for medal-hook64.dll: 0x%llx.\n", medal_tv );

				if ( !medal_tv )
				{

					if ( qtx_device->free( loader_addr ) )
					{
						ldr_mdl = 0;
						loader_addr = 0;
						present_address = 0;
						old_present_ptr = 0;
						ldr_data_ptr = 0;

						qtx_device->remove_vad( base );

						VirtualFree( reinterpret_cast< PVOID > (buffer), 0, MEM_RELEASE );
					}
					else
						rwx_log( "failed to terminate loader.\n" );

					return qtx::operation_failed;
				}

				const uintptr_t present = qtx_device->find_signature( medal_tv, "FF 15 ?? ?? ?? ?? 48 8B 03 88 82 CB 5F 50 ?? 8B C6" );

				rwx_log( "present pointer for medal.tv: 0x%llx.\n", present );

				int32_t offset = 0;

				qtx_device->read_physical_memory( present + 2, &offset, sizeof( offset ) );

				present_address = present + offset + 6;

			}

			else if ( method == 2 )
			{
				const uintptr_t discordhook = qtx_device->get_module_base( "DiscordHook64.dll" );

				rwx_log( "module for discord overlay: 0x%llx.\n", discordhook );

				if ( !discordhook )
				{

					if ( qtx_device->free( loader_addr ) )
					{
						ldr_mdl = 0;
						loader_addr = 0;
						present_address = 0;
						old_present_ptr = 0;
						ldr_data_ptr = 0;

						qtx_device->remove_vad( base );

						VirtualFree( reinterpret_cast< PVOID > (buffer), 0, MEM_RELEASE );
					}
					else
						rwx_log( "failed to terminate loader.\n" );

					return qtx::operation_failed;
				}

				const uintptr_t present = qtx_device->find_signature( discordhook, "9F 89 F0 13 15 ?? ?? ?? ?? 89 C6 48 8D 4C 24 ??" ) + 3;

				rwx_log( "present pointer for discord overlay: 0x%llx.\n", present );

				int32_t offset = 0;

				qtx_device->read_physical_memory( present + 2, &offset, sizeof( offset ) );

				present_address = present + offset + 6;

			}

			else if ( method == 3 )
			{
				rwx_log( "fatal error occured.\n" );

				return qtx::operation_failed;
			}

			rwx_log( "present_address (non-rva): 0x%llx.\n", present_address );

			uintptr_t old_ptr = qtx_device->swap_virtual_pointer( present_address, loader_addr );

			old_present_ptr = old_ptr;

			rwx_log( "shellcode executed, waited on response from dllmain...\n" );

			int count = 0;

			VM_EAGLE_WHITE_END;

			do
			{
				if ( !qtx_device->read_physical_memory( ldr_data_ptr, &ldr, sizeof( payload_data ) ) )
				{
					rwx_log( "payload read failed: %llx.\n", ldr_data_ptr );
					count++;

					if ( count >= 8 )
					{
						break;
					}
				}
			} while ( ldr.status != LOADER_STATUS_EXECUTE );

			VM_FISH_WHITE_START;

			rwx_log( "dllmain successfully invoked from payload data ptr: %llx.\n", ldr_data_ptr );

			if ( old_present_ptr && !qtx_device->swap_virtual_pointer( present_address, old_present_ptr ) )
			{
				rwx_log( "failed to restore old pointer.\n" );

				return qtx::operation_failed;
			}

			if ( !qtx_device->free( loader_addr ) )
			{
				rwx_log( "failed to terminate loader.\n" );

				return qtx::operation_failed;
			}

			ldr_mdl = 0;
			loader_addr = 0;
			present_address = 0;
			old_present_ptr = 0;
			ldr_data_ptr = 0;

			VM_FISH_WHITE_END;

			qtx_device->remove_vad( base );

			VM_SHARK_WHITE_START

			VirtualFree( reinterpret_cast< PVOID > (buffer), 0, MEM_RELEASE );

			VM_SHARK_WHITE_END
		}

		//VM_TIGER_WHITE_END;

		return qtx::operation_succesful;
	}
};

static rwx* map = new rwx( );