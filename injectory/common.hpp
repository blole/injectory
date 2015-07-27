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
#pragma once
#include <Windows.h>
#include <stdio.h>

#include <boost/filesystem/path.hpp>
using boost::filesystem::path;

#include <locale>
#include <codecvt>
#include <string>
using std::string;
using std::wstring;
using std::shared_ptr;



#define PRINT_ERROR_MSGA(...) { printf("Error: [@%s] ", __FUNCTION__); PrintErrorMsgA(__VA_ARGS__); }
#define PRINT_ERROR_MSGW(...) { wprintf(L"Error: [@%s] ", __FUNCTIONW__); PrintErrorMsgW(__VA_ARGS__); }

void PrintErrorMsgA(char *format, ...);
void PrintErrorMsgW(wchar_t *format, ...);

wchar_t *__stdcall char_to_wchar_t(const char *src);

char *alloc_stra(char *in_str);

int parse_int(const char *str);

///a process id
typedef DWORD pid_t;

///a thread id
typedef DWORD tid_t;

///a handle
typedef HANDLE handle_t;

namespace std
{
	inline string to_string(const wstring& s)
	{
		static std::wstring_convert<std::codecvt_utf8<wchar_t>> to_wstring_converter;
		return to_wstring_converter.to_bytes(s);
	}
	inline wstring to_wstring(const string& s)
	{
		static std::wstring_convert<std::codecvt_utf8<wchar_t>> to_wstring_converter;
		return to_wstring_converter.from_bytes(s);
	}
}
