////////////////////////////////////////////////////////////////////////////////////////////
// loader: command-line interface dll injector
// Copyright (C) 2009-2011 wadim <wdmegrv@gmail.com>
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
#ifndef _MISC_H
#define _MISC_H

#include <Windows.h>
#include <stdio.h>

#if defined(_WIN64)
	#define CHECK_TARGET_PROC(pid) IsProcess64(pid) != 0
	#define BIT_ERROR_STRING	"injectory.x64 doesn't support x86 processes"
#elif defined(_WIN32)
	#define CHECK_TARGET_PROC(pid) IsProcess64(pid) != 1
	#define BIT_ERROR_STRING	"injectory.x86 doesn't support x64 processes"
#endif

#define PRINT_TARGET_PROC_ERROR(pid) printf("error: " BIT_ERROR_STRING " (%d).\n", pid)
#define THROW_IF_TARGET_BIT_MISMATCH(pid)												\
{																						\
	if (CHECK_TARGET_PROC(pid))															\
		throw std::runtime_error(BIT_ERROR_STRING " (" + std::to_string(pid) + ")");	\
}


#define PRINT_ERROR_MSGA(...) { printf("Error: [@%s] ", __FUNCTION__); PrintErrorMsgA(__VA_ARGS__); }
#define PRINT_ERROR_MSGW(...) { wprintf(L"Error: [@%s] ", __FUNCTIONW__); PrintErrorMsgW(__VA_ARGS__); }

void PrintErrorMsgA(char *format, ...);
void PrintErrorMsgW(wchar_t *format, ...);

wchar_t *__stdcall char_to_wchar_t(const char *src);

char *alloc_stra(char *in_str);

int parse_int(const char *str);

#endif // _MISC_H