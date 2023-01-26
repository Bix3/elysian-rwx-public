#pragma once
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>

void custom_print( const char* str, ... )
{
	VM_TIGER_WHITE_START;
	time_t now = time( 0 );
	tm* ltm = localtime( &now );

	std::cout << _("[") << 5 + ltm->tm_hour << _(":");
	std::cout << 30 + ltm->tm_min << _(":");
	std::cout << ltm->tm_sec << _("] ");

	char buffer [ 4096 ];
	va_list args;
	va_start( args, str );
	int rc = vsnprintf( buffer, sizeof( buffer ), str, args );
	va_end( args );

	std::cout << buffer;
	VM_TIGER_WHITE_END;
}


#define rwx_log(a, ...) printf(_(" ")); custom_print(a, ##__VA_ARGS__ )

namespace utl
{
	auto get_process_id( std::string name ) -> int
	{
		const auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

		PROCESSENTRY32 entry { };
		entry.dwSize = sizeof( PROCESSENTRY32 );

		Process32First( snapshot, &entry );
		do
		{
			if ( !name.compare( entry.szExeFile ) )
			{
				VM_TIGER_WHITE_END;
				return entry.th32ProcessID;
			}

		} while ( Process32Next( snapshot, &entry ) );

		return 0;
	}

	auto read_file( const std::string filename ) -> std::vector<uint8_t>
	{
		VM_TIGER_WHITE_START;
		std::ifstream stream( filename, std::ios::binary );

		std::vector<uint8_t> buffer { };

		buffer.assign( (std::istreambuf_iterator<char>( stream )), std::istreambuf_iterator<char>( ) );

		stream.close( );

		VM_TIGER_WHITE_END;
		return buffer;
	}

	namespace threads
	{
		typedef struct _CLIENT_ID_N
		{
			HANDLE UniqueProcess;
			HANDLE UniqueThread;
		} CLIENT_ID_N;

		typedef struct _THREAD_BASIC_INFORMATION
		{
			NTSTATUS ExitStatus;
			PVOID TebBaseAddress;
			CLIENT_ID_N ClientId;
			KAFFINITY AffinityMask;
			LONG Priority;
			LONG BasePriority;
		} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


		std::vector<ULONG> WalkProcessThreads( ULONG ProcessId )
		{
			VM_TIGER_WHITE_START;
			std::vector<ULONG> ThreadIds {};
			THREADENTRY32 TE32;

			HANDLE Handle = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
			if ( Handle == INVALID_HANDLE_VALUE )
				return {}; 

			TE32.dwSize = sizeof( THREADENTRY32 );
			if ( !Thread32First( Handle, &TE32 ) )
			{
				CloseHandle( Handle );
				return {};
			}

			do
			{
				if ( TE32.th32OwnerProcessID == ProcessId )
				{
					ThreadIds.push_back( TE32.th32ThreadID );
				}
			} while ( Thread32Next( Handle, &TE32 ) );

			CloseHandle( Handle );

			VM_TIGER_WHITE_END;
			return ThreadIds;
		}

		PVOID get_last_thread_stack( int pid )
		{
			std::vector<PVOID> ThreadStacks {};

			typedef NTSTATUS( NTAPI* _NtQueryInformationThread ) (
				HANDLE ThreadHandle,
				ULONG ThreadInformationClass,
				PVOID ThreadInformation,
				ULONG ThreadInformationLength,
				PULONG ReturnLength
				);
			_NtQueryInformationThread NtQueryInformationThread = ( _NtQueryInformationThread ) GetProcAddress( LoadLibraryW( _(L"ntdll.dll") ), _("NtQueryInformationThread") );

			std::vector<ULONG> ThreadIds = WalkProcessThreads( pid );
			for ( ULONG ThreadId : ThreadIds )
			{
				THREAD_BASIC_INFORMATION TBI;
				NT_TIB TIB;

				HANDLE Handle = OpenThread( THREAD_QUERY_LIMITED_INFORMATION, FALSE, ThreadId );
				NtQueryInformationThread( Handle, 0x0, &TBI, sizeof( THREAD_BASIC_INFORMATION ), NULL );
				qtx_device->read_physical_memory( ( uintptr_t ) TBI.TebBaseAddress, &TIB, sizeof( TIB ) );

				ThreadStacks.push_back( TIB.StackLimit );
			}

			PVOID LastThreadStack = 0;
			for ( UINT i = 0; i < ThreadStacks.size( ); i++ )
			{
				if ( ThreadStacks [ i ] > LastThreadStack )
					LastThreadStack = ThreadStacks [ i ];
			}

			ULONG qm_region_size = 0;
			PVOID qm_base_address = 0;

			qtx_device->query_memory( ( uintptr_t ) LastThreadStack, ( uintptr_t* ) &qm_base_address, NULL, &qm_region_size );

			return ( PVOID ) (( ULONGLONG ) qm_base_address + qm_region_size);
		}
	}
}