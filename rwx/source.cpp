#include <impl/includes.h>

#define msg_box(str) MessageBox(0, _(str), _("rwx-meme"), 0 );


auto determine_meme( std::string name ) -> int32_t
{
	// why??? just why?? ignore all this pls.

	if ( strcmp( name.c_str(), _("medal") ) == 0 )
		return 1;

	if ( strcmp( name.c_str( ), _("discord") ) == 0 )
		return 2;

	return 3;
}

auto main( int argc, char* argv[ ] ) -> void
{
	VM_TIGER_WHITE_START;

	SetConsoleTitleA( _( "rwx-meme" ) );

	if ( argc > 1 )
	{
		if ( !strcmp( argv [ argc - 1 ], ("--test") ) )
		{
			if ( !qtx_device->is_mapped( ) )
			{
				msg_box( "driver is not loaded." );
				return;
			}

			msg_box( "driver is loaded." );
			return;
		}

		printf( _( "\n rwx-meme by elysian software development (c)\n\n bluescreens, exceptions & errors can occur in the current stage of development.\n please be careful, and don't leak pls.\n\n" ) );

		rwx_log( _( "please press any key to continue.\n" ) );

		std::getchar( );
	}


	if ( argc < 4 ) {
		printf( _( "usage: rwx.exe <discord/medal> <process> <module>\n" ) );
		return;
	}


	if ( !qtx_device->is_mapped( ) )
	{
		msg_box( "driver is not loaded." );
		return;
	}


	int32_t result = determine_meme( argv [ 1 ] );

	switch ( result )
	{
	case 3:
		rwx_log( _( "incorrect arguments for injection.\n" ) );
	}

	const int32_t pid = utl::get_process_id( argv [ 2 ] );

	if ( !pid )
		return;

	qtx_device->attach( pid );

	rwx_log( _( "rwx-memeing: %s\n" ), argv [ 2 ], pid, argv [ 3 ] );

	if ( map->meme( pid, utl::read_file( argv [ 3 ] ).data( ), result ) != qtx::operation_succesful )
	{
		rwx_log( _( "rwx-meme has failed the operation.\n" ) );

		goto unload;
	}

	rwx_log( _( "rwx-meme has successfully completed the operation.\n" ) );

	goto unload;

	VM_TIGER_WHITE_END;

unload:

	std::cin.get( );

	if ( qtx_device->unload_meme( ) )
	{
		rwx_log( _( "meme has been unloaded.\n" ) );
	}
	else
	{
		rwx_log( _( "meme has failed to unload, please restart your machine.\n" ) );
	}
}

