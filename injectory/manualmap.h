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
#ifndef _MANUALMAP_H
#define _MANUALMAP_H

#undef UNICODE

#include <stdio.h>

#include <Windows.h>
#include <TlHelp32.h>

#include "misc.h"
#include "dllmain_remotecall.h"
#include "generic_injector.h"
#include "injector_helper.h"

BOOL
MapRemoteModuleW(
	DWORD dwProcessId,
	LPCWSTR lpModulePath
	);

BOOL
MapRemoteModuleA(
	DWORD dwProcessId,
	LPCSTR lpModulePath
	);

#endif // _MANUALMAP_H