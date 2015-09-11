#pragma once
#undef UNICODE
#include "injectory/common.hpp"
#include <TlHelp32.h>

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
