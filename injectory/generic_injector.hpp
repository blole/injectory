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
#ifndef _GENERIC_INJECTOR_H
#define _GENERIC_INJECTOR_H

#include <stdio.h>

#include <Windows.h>

#include "misc.hpp"
#include "injector_helper.hpp"

// INFINITE can cause DeadLock if host process is in debug mode
#define INJLIB_WAITTIMEOUT		INFINITE
#define WII_WAITTIMEOUT			5000

BOOL
InjectLibraryW(
	DWORD dwProcessId,
	LPCWSTR lpLibPath
	);

BOOL
InjectLibraryA(
	DWORD dwProcessId,
	LPCSTR lpLibPath
	);

BOOL
EjectLibrary(
	DWORD dwProcessId,
	LPVOID lpModule
	);

BOOL
EjectLibraryW(
	DWORD dwProcessId,
	LPCWSTR lpLibPath
	);

BOOL
EjectLibraryA(
	DWORD dwProcessId,
	LPCSTR lpLibPath
	);

BOOL
InjectLibraryOnStartupW(
	LPCWSTR lpLibPath,
	LPCWSTR lpProcPath,
	LPWSTR lpProcArgs,
	BOOL bWaitForInputIdle
	);

BOOL
InjectLibraryOnStartupA(
	LPCSTR lpLibPath,
	LPCSTR lpProcPath,
	LPSTR lpProcArgs,
	BOOL bWaitForInputIdle
	);

BOOL
EjectLibraryOnStartupW(
	LPCWSTR lpLibPath,
	LPCWSTR lpProcPath,
	LPWSTR lpProcArgs,
	BOOL bWaitForInputIdle
	);

BOOL 
EjectLibraryOnStartupA(
	LPCSTR lpLibPath,
	LPCSTR lpProcPath,
	LPSTR lpProcArgs,
	BOOL bWaitForInputIdle
	);

#endif // _GENERIC_INJECTOR_H