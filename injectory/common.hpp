#pragma once
#include <Windows.h>

#include <boost/filesystem.hpp>
using boost::filesystem::path;

#include <locale>
#include <codecvt>
using std::shared_ptr;
#include <string>
using std::string;
using std::wstring;
#include <vector>
using std::vector;


#if defined(_WIN64)
	const bool is64bit = true;
#elif defined(_WIN32)
	const bool is64bit = false;
#endif

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)


#define PRINT_ERROR_MSGA(...) { printf("Error: [@%s] ", __FUNCTION__); PrintErrorMsgA(__VA_ARGS__); }
#define PRINT_ERROR_MSGW(...) { wprintf(L"Error: [@%s] ", __FUNCTIONW__); PrintErrorMsgW(__VA_ARGS__); }

void PrintErrorMsgA(char *format, ...);
void PrintErrorMsgW(wchar_t *format, ...);

// a process id
typedef DWORD pid_t;
// a thread id
typedef DWORD tid_t;
// a handle
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

SYSTEM_INFO getSystemInfo();
SYSTEM_INFO getNativeSystemInfo();

DWORD WaitForSingleObject_Throwing(HANDLE handle, DWORD millis);
