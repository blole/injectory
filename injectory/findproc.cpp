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

BOOL CALLBACK EWP_DirectInject(HWND hwnd, LPARAM lParam)
{
	CHAR name[500] = {0};
	struct INJ_DATA injdata = *(struct INJ_DATA*)lParam;

	// injection via windowtitle
	if(injdata.mode == 1)
	{
		GetWindowTextA(hwnd, name, 500 * sizeof(CHAR));

		if(strncmp((LPCSTR)injdata.name, name, strlen(name) + 1) == 0)
		{
			DWORD dwPid = 0;
			GetWindowThreadProcessId(hwnd, &dwPid);
			if(dwPid == 0)
			{
				PRINT_ERROR_MSGA("Could not get ProcessId from window handle (hwnd: 0x%p).",
					hwnd);
			}

			if(!CHECK_TARGET_PROC(dwPid))
			{
				PRINT_TARGET_PROC_ERROR(dwPid);
				return TRUE;
			}

			if(injdata.inject)
			{
				if (injdata.mm)
					MapRemoteModule(dwPid, injdata.libpath);
				else
					Process::open(dwPid).inject(injdata.libpath);
			}
			else
			{
				if(injdata.module_address)
				{
					EjectLibrary(dwPid, injdata.module_address);
				}
				else
				{
					EjectLibraryA(dwPid, injdata.libpath);
				}
			}
		}
	}

	// injection via windowclass
	if(injdata.mode == 2)
	{
		GetClassNameA(hwnd, name, 500 * sizeof(CHAR));
		if(strncmp((LPCSTR)injdata.name, name, strlen(name) + 1) == 0)
		{
			DWORD dwPid = 0;
			GetWindowThreadProcessId(hwnd, &dwPid);
			if(dwPid == 0)
			{
				PRINT_ERROR_MSGA("Could not get ProcessId from window handle (hwnd: 0x%p).",
					hwnd);
			}

			if(!CHECK_TARGET_PROC(dwPid))
			{
				PRINT_TARGET_PROC_ERROR(dwPid);
				return TRUE;
			}

			if(injdata.inject)
			{
				if(injdata.mm)
					MapRemoteModule(dwPid, injdata.libpath);
				else
					Process::open(dwPid).inject(injdata.libpath);
			}
			else
			{
				if(injdata.module_address)
				{
					EjectLibrary(dwPid, injdata.module_address);
				}
				else
				{
					EjectLibraryA(dwPid, injdata.libpath);
				}
			}
		}
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
				if(!CHECK_TARGET_PROC(pid))
				{
					PRINT_TARGET_PROC_ERROR(pid);
					continue;
				}

				bFound = TRUE;

				if(inject)
				{
					if(mm)
						MapRemoteModule(pid, lpLibPath);
					else
						Process::open(pid).inject(lpLibPath);
				}
				else
				{
					if(lpModule)
					{
						if(!EjectLibrary(pid, lpModule))
						{
							PRINT_ERROR_MSGA("Ejection failed. (PID: %d)", pid);
						}
					}
					else
					{
						if(!EjectLibraryA(pid, lpLibPath))
						{
							PRINT_ERROR_MSGA("Ejection failed. (PID: %d)", pid);
						}
					}
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