#pragma once

/* 
*	VM_VIRTUALIZATION:
* 
*	Define this when you're ready to field test and virtualize with Themida. 
*/

//#define VM_VIRTUALIZATION

//themida
#include <impl/themida/includes/ThemidaSDK.h>

// source
#include <windows.h>
#include <iostream>
#include <string>
#include <libloaderapi.h>
#include <cstdint>
#include <rpcasync.h>
#include <wtypes.h>
#include <TlHelp32.h>
#include <vector>
#include <fstream>

// qtx
#include <impl/qtx/qtx_forceinline.hpp>
#include <impl/qtx/qtx_handle.hpp>
#include <impl/qtx/qtx_data.hpp>
#include <impl/qtx/qtx_utl.hpp>

// rwx
#include <impl/rwx/rwx_meme.hpp>

