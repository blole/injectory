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
#include "injectory/findproc.hpp"
#include "injectory/process.hpp"
#include "injectory/exception.hpp"


#define PRINT_TARGET_PROC_ERROR(pid) printf("error: this and target process bit mismatch (x64 vs. x86) (%d).\n", pid)


BOOL CALLBACK EWP_DirectInject(HWND hwnd, LPARAM lParam)
{
	CHAR name[500] = {0};
	struct INJ_DATA injdata = *(struct INJ_DATA*)lParam;

	if (injdata.mode == 1) // injection via windowtitle
		GetWindowTextA(hwnd, name, 500 * sizeof(CHAR));
	else if (injdata.mode == 2) // injection via windowclass
		GetClassNameA(hwnd, name, 500 * sizeof(CHAR));

	DWORD pid = 0;
	
	if (strncmp((LPCSTR)injdata.name, name, strlen(name) + 1) == 0)
	{
		GetWindowThreadProcessId(hwnd, &pid);
		if (pid == 0)
			PRINT_ERROR_MSGA("Could not get ProcessId from window handle (hwnd: 0x%p).", hwnd);
	}

	Process proc = Process::open(pid);

	if (Process::open(pid).is64bit() != is64bit)
	{
		PRINT_TARGET_PROC_ERROR(pid);
		return TRUE;
	}

	if (injdata.inject)
	{
		if (injdata.mm)
			proc.mapRemoteModule(injdata.libpath);
		else
			proc.inject(injdata.libpath);
	}
	else
	{
		if (injdata.module_address)
			proc.eject(Module((HMODULE)injdata.module_address));
		else
			proc.eject(injdata.libpath);
	}

	return TRUE;
}

BOOL InjectEjectToWindowTitleA(LPCSTR lpWindowName, LPCSTR lpLibPath, LPVOID lpModule, BOOL inject, BOOL mm)
{
	struct INJ_DATA injdata = {1, lpWindowName, lpLibPath, lpModule, inject, mm};
	
	if(!EnumWindows((WNDENUMPROC)&EWP_DirectInject, (LPARAM)&injdata))
	{
		DWORD dwLastError = GetLastError();
		if(dwLastError)
		{
			PRINT_ERROR_MSGA("EnumWindows failed.");
			return FALSE;
		}
	}

	return TRUE;
}

BOOL InjectEjectToWindowClassA(LPCSTR lpClassName, LPCSTR lpLibPath, LPVOID lpModule, BOOL inject, BOOL mm)
{
	struct INJ_DATA injdata = {2, lpClassName, lpLibPath, lpModule, inject, mm};

	if(!EnumWindows((WNDENUMPROC)&EWP_DirectInject, (LPARAM)&injdata))
	{
		DWORD dwLastError = GetLastError();
		if(dwLastError)
		{
			PRINT_ERROR_MSGA("EnumWindows failed.");
			return FALSE;
		}
	}

	return TRUE;
}

BOOL InjectEjectToProcessNameA(LPCSTR lpProcName, LPCSTR lpLibPath, LPVOID lpModule, BOOL inject, BOOL mm)
{
	PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
	pid_t& pid = pe32.th32ProcessID;
	HANDLE hProcSnap = 0;
	BOOL bFound = FALSE;
	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hProcSnap == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR_MSGA("Could not get process snapshot.");
		return FALSE;
	}

	if(Process32First(hProcSnap, &pe32))
	{
		do
		{
			if(!strncmp(lpProcName, pe32.szExeFile, strlen(lpProcName)))
			{
				if(Process::open(pid).is64bit() != is64bit)
				{
					PRINT_TARGET_PROC_ERROR(pid);
					continue;
				}

				bFound = TRUE;

				if(inject)
				{
					if(mm)
						Process::open(pid).mapRemoteModule(lpLibPath);
					else
						Process::open(pid).inject(lpLibPath);
				}
				else
				{
					if (lpModule)
						Process::open(pid).eject(Module((HMODULE)lpModule));
					else
						Process::open(pid).eject(lpLibPath);
				}
			}
		}
		while(Process32Next(hProcSnap, &pe32));
	}

	CloseHandle(hProcSnap);

	if(!bFound)
	{
		PRINT_ERROR_MSGA("Could not find process (%s).", lpProcName);
	}

	return bFound;
}