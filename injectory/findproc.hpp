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
#pragma once
#include <Windows.h>

#undef UNICODE

#include <TlHelp32.h>

#include "injectory/misc.hpp"
#include "injectory/generic_injector.hpp"
#include "injectory/manualmap.hpp"

struct INJ_DATA
{
	BYTE mode;
	LPCSTR name;
	LPCSTR libpath;
	LPVOID module_address;
	BOOL inject;
	BOOL mm;
};

BOOL InjectEjectToWindowTitleA(LPCSTR lpWindowName, LPCSTR lpLibPath, LPVOID lpModule, BOOL inject, BOOL mm);
BOOL InjectEjectToWindowClassA(LPCSTR lpClassName, LPCSTR lpLibPath, LPVOID lpModule, BOOL inject, BOOL mm);
BOOL InjectEjectToProcessNameA(LPCSTR lpProcName, LPCSTR lpLibPath, LPVOID lpModule, BOOL inject, BOOL mm);
