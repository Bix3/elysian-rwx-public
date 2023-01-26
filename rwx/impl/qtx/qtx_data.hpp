#pragma once
#include <../qtx/impl/communication/interface.h>

#pragma warning(disable : 4996)

class qtx_interface_t
{
private:

private:
	int pid = 0;
public:

	inline auto attach( int a_pid ) -> bool
	{
		if ( !a_pid )
			return false;

		pid = a_pid;

		return true;
	}

	inline auto is_mapped( ) -> bool
	{
		VM_FISH_BLACK_START;


		return true;
	}

	inline auto send_cmd( void* data, requests code ) -> bool
	{


		return true;
	}

	inline auto get_module_base( const char* module_name ) -> const std::uintptr_t
	{
		base_invoke data { 0 };

		data.pid = pid;
		data.handle = 0;
		data.name = module_name;

		send_cmd( &data, invoke_base );

		return data.handle;
	}

	inline auto write_physical_memory( const std::uintptr_t address, void* buffer, const std::size_t size ) -> bool
	{
		write_invoke data { 0 };

		data.pid = pid;
		data.address = address;
		data.buffer = buffer;
		data.size = size;

		return send_cmd( &data, invoke_write );
	}

	template <typename t>
	inline auto write_physical_memory( const std::uintptr_t address, t value ) -> bool
	{
		return this->write_physical_memory( address, &value, sizeof( t ) );
	}

	inline auto free( const std::uintptr_t address )
	{
		free_invoke data { 0 };

		data.pid = pid;
		data.address = address;

		return send_cmd( &data, invoke_free );
	}

	inline auto remove_vad( const std::uintptr_t address )
	{
		remove_node_invoke data { 0 };

		data.pid = pid;
		data.address = address;

		return send_cmd( &data, invoke_remove_node );
	}

	inline auto unload_meme( ) -> bool
	{
		unload_invoke data { 0 };

		send_cmd( &data, invoke_unload );

		return data.unloaded;
	}

	inline auto read_physical_memory( const std::uintptr_t address, void* buffer, const std::size_t size ) -> bool
	{
		read_invoke data { 0 };

		data.pid = pid;
		data.address = address;
		data.buffer = buffer;
		data.size = size;

		return send_cmd( &data, invoke_read );
	}

	template <typename t>
	inline t read_physical_memory( const std::uintptr_t address )
	{
		t response { };
		read_physical_memory( address, &response, sizeof( t ) );
		return response;
	}

	inline auto find_signature( const std::uintptr_t base, const std::string signature ) -> std::uintptr_t
	{
		pattern_invoke data { 0 };

		data.pid = pid;
		data.base = base;
		data.address = 0;

		memset( data.signature, 0, sizeof( char ) * 260 );
		strcpy( data.signature, signature.c_str( ) );

		send_cmd( &data, invoke_pattern );

		return data.address;
	}

	inline bool allocate_memory( uintptr_t& base, const size_t size )
	{
		allocate_invoke  data;

		data.pid = pid;
		data.base = base;
		data.size = size;

		send_cmd( &data, invoke_allocate );

		base = data.base;
		return data.base != 0;
	}

	inline bool query_memory( const uintptr_t addr, uintptr_t* page_base, uint32_t* page_prot, ULONG* page_size )
	{
		query_memory_invoke  data;

		data.pid = pid;
		data.address = addr;

		bool result = send_cmd( &data, invoke_query_memory );

		if ( page_base ) *page_base = data.page_base;
		if ( page_prot ) *page_prot = data.page_prot;
		if ( page_size ) *page_size = data.page_size;

		return result;
	}


	inline auto swap_virtual_pointer( std::uintptr_t src, std::uintptr_t dst ) -> std::uintptr_t
	{
		swap_invoke data { 0 };

		data.pid = pid;
		data.src = src;
		data.dst = dst;
		data.old = 0;

		send_cmd( &data, invoke_swap );

		return data.old;
	}
};

static qtx_interface_t* qtx_device = new qtx_interface_t( );