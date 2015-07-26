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
#ifndef _DLLMAIN_REMOTECALL_H
#define _DLLMAIN_REMOTECALL_H

#include <Windows.h>

#include "injectory/misc.hpp"
#include "injectory/generic_injector.hpp"

typedef BOOL (__stdcall *DLLMAIN)(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

struct DLLMAINCALL
{
	DLLMAIN fpDllMain;
	HMODULE hModule;
	DWORD ul_reason_for_call;
	LPVOID lpReserved;
};

BOOL RemoteDllMainCall(HANDLE hProcess, LPVOID lpModuleEntry, HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

#endif // _DLLMAIN_REMOTECALL_H