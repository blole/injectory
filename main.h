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
#ifndef _MAIN_H
#define _MAIN_H

#ifdef UNICODE
#undef UNICODE
#endif

#if defined(_WIN64)
#pragma message("_WIN64 defined")
#elif defined(_WIN32)
#pragma message("_WIN32 defined")
#endif

#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>

#include "misc.h"
#include "findproc.h"
#include "injector_helper.h"
#include "generic_injector.h"
#include "manualmap.h"

#define VERSION "4.1"
#define CMP_OPT(option) compare_option(option, argv[argv_index])

const char *option_list[] =
{
	"--help"		,
	"--eject"		,
	"--dbgpriv"		,
	"--wii"			,
	"--pid"			,
	"--procname"	,
	"--wndtitle"	,
	"--wndclass"	,
	"--lib"			,
	"--launch"		,
	"--args"		,
	"--mm"			,
	"--listmodules"
};

enum option_enum
{
	o_help			= 0,
	o_eject			= 1,
	o_dbgpriv		= 2,
	o_wii			= 3,
	o_pid			= 4,
	o_procname		= 5,
	o_wndtitle		= 6,
	o_wndclass		= 7,
	o_lib			= 8,
	o_launch		= 9,
	o_args			= 10,
	o_mm			= 11,
	o_listmodules	= 12
};

#endif // _MAIN_H