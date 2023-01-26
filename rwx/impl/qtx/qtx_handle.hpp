#pragma once

enum programs
{
	r6,
	apex,
	eft,
	valorant,
	sot,
	unturned
};

namespace qtx
{
	enum status
	{
		operation_succesful,
		operation_failed,
	};

	namespace handler
	{
		__forceinline std::string program( programs index )
		{
			switch ( index )
			{
			case r6:
				return _( "RainbowSix.exe" );

			case apex:
				return _( "r5apex.exe" );

			case eft:
				return _( "EscapeFromTarkov.exe" );

			case valorant:
				return _( "VALORANT-Win64-Shipping.exe" );

			case sot:
				return _( "SoTGame.exe" );

			case unturned:
				return _( "Unturned.exe" );
			}

		}
	}
}