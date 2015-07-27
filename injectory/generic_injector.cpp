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
#include "injectory/generic_injector.hpp"
#include "injectory/exception.hpp"

#include <functional>
using namespace std;

BOOL
EjectLibrary(
	DWORD pid,
	LPVOID lpModule
	)
{
	BOOL bRet = FALSE;
	HANDLE hProcess = 0;
	HANDLE hThread = 0;
	HMODULE kernel32dll = 0;
	LPTHREAD_START_ROUTINE lpFreeLibrary = 0;
	DWORD dwThreadId = 0;
	DWORD dwExitCode = 0;

	__try
	{
		kernel32dll = GetModuleHandleW(L"Kernel32");
		if(!kernel32dll)
		{
			PRINT_ERROR_MSGA("Could not get handle to Kernel32.");
			__leave;
		}

		lpFreeLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(kernel32dll, "FreeLibrary");
		if(lpFreeLibrary == 0)
		{
			PRINT_ERROR_MSGA("Could not get the address of FreeLibrary.");
			__leave;
		}

		// Get a handle for the target process.
		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION	|	// Required by Alpha
			PROCESS_CREATE_THREAD		|	// For CreateRemoteThread
			PROCESS_VM_OPERATION		|	// For VirtualAllocEx/VirtualFreeEx
			PROCESS_VM_WRITE			|	// For WriteProcessMemory
			PROCESS_VM_READ,
			FALSE, 
			pid);
		if(!hProcess)
		{
			PRINT_ERROR_MSGA("Could not get handle to process (PID: %d).", pid);
			__leave;
		}

		//TODO: SuspendResumeProcess(pid, false);

		hThread = CreateRemoteThread(
			hProcess,
			0,
			0,
			lpFreeLibrary,
			lpModule,
			0,
			&dwThreadId);
		if(hThread == 0)
		{
			PRINT_ERROR_MSGA("Could not create thread in remote process.");
			__leave;
		}

		if(!SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL))
		{
			PRINT_ERROR_MSGA("Could not set thread priority.");
			__leave;
		}

		HideThreadFromDebugger(dwThreadId);

		// Wait for the remote thread to terminate
		if(WaitForSingleObject(hThread, INJLIB_WAITTIMEOUT) == WAIT_FAILED)
		{
			printf("Error: WaitForSingleObject failed.");
			__leave;
		}

		if(!GetExitCodeThread(hThread, &dwExitCode))
		{
			printf("Error: Could not get thread exit code.");
			__leave;
		}

		// Check FreeLibrary
		if(!dwExitCode)
		{
			// error: ejection failed
			// - invalid PE header?
			printf("Error: Call to FreeLibrary in remote process failed.\n");
			__leave;
		}

		printf("Successfully ejected (0x%p | PID: %d):\n\n"
			"  ExitCodeThread: 0x%08x\n",
			lpModule,
			pid,
			dwExitCode);

		bRet = TRUE;
	}
	__finally
	{
		if(hThread)
		{
			CloseHandle(hThread);
		}

		if(hProcess)
		{
			CloseHandle(hProcess);
		}

		//TODO: SuspendResumeProcess(pid, true);
	}

	return bRet;
}

BOOL
EjectLibraryW(
	DWORD dwProcessId,
	LPCWSTR lpLibPath
	)
{
	BOOL bRet = FALSE;
	SIZE_T Memory = 0;
	SYSTEM_INFO sys_info = {0};
	WCHAR NtMappedFileName[MAX_PATH + 1] = {0};
	WCHAR NtFileNameThis[MAX_PATH + 1] = {0};
	MEMORY_BASIC_INFORMATION mem_basic_info	= {0};
	HANDLE hProcess = 0;
	
	__try
	{
		// Get a handle for the target process.
		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION	|	// Required by Alpha
			PROCESS_CREATE_THREAD		|	// For CreateRemoteThread
			PROCESS_VM_OPERATION		|	// For VirtualAllocEx/VirtualFreeEx
			PROCESS_VM_WRITE			|	// For WriteProcessMemory
			PROCESS_VM_READ,
			FALSE, 
		dwProcessId);
		if(!hProcess)
		{
			PRINT_ERROR_MSGA("Could not get handle to process.");
			__leave;
		}

		if(!GetFileNameNtW(lpLibPath, NtFileNameThis, MAX_PATH))
		{
			PRINT_ERROR_MSGA("Could not get the NT namespace path.");
			__leave;
		}

		GetSystemInfo(&sys_info);
	
		for(Memory = 0;
			Memory < (SIZE_T)sys_info.lpMaximumApplicationAddress;
			Memory += mem_basic_info.RegionSize)
		{
			SIZE_T vqr = VirtualQueryEx(
			hProcess,
			(LPCVOID)Memory,
			&mem_basic_info,
			sizeof(MEMORY_BASIC_INFORMATION));
			if(vqr != 0)
			{
				if((mem_basic_info.AllocationProtect & PAGE_EXECUTE_WRITECOPY) && 
					(mem_basic_info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
				{
					if(GetMappedFileNameW(
						hProcess,
						(HMODULE)mem_basic_info.AllocationBase,
						NtMappedFileName,
						MAX_PATH) == 0)
					{
						PRINT_ERROR_MSGA("GetMappedFileNameW failed.");
						__leave;
					}

					if(wcsncmp(NtFileNameThis, NtMappedFileName, wcslen(NtMappedFileName) + 1) == 0)
					{
						if(!EjectLibrary(dwProcessId, mem_basic_info.AllocationBase))
						{
							PRINT_ERROR_MSGA("Ejection failed. (AllocationBase: 0x%p | PID: %d)", mem_basic_info.AllocationBase, dwProcessId);
						}
					}
				}
			}
			// VirtualQueryEx failed
			else
			{
				PRINT_ERROR_MSGA("VirtualQueryEx failed.");
				__leave;
			}
		}

		bRet = TRUE;
	}
	__finally
	{
		if(hProcess)
		{
			CloseHandle(hProcess);
		}
	}

	return bRet;
}

BOOL
EjectLibraryA(
	DWORD dwProcessId,
	LPCSTR lpLibPath
	)
{
	BOOL bRet = FALSE;
	wchar_t *libpath = char_to_wchar_t(lpLibPath);

	if(libpath == 0)
	{
		return bRet;
	}

	bRet = EjectLibraryW(dwProcessId, libpath);

	if(libpath)
	{
		free(libpath);
	}
	
	return bRet;
}

BOOL
EjectLibraryOnStartupW(
	LPCWSTR lpLibPath,
	LPCWSTR lpProcPath,
	LPWSTR lpProcArgs,
	BOOL bWaitForInputIdle
	)
{
	BOOL				bRet	= FALSE;
	STARTUPINFO			si		= {0};
	PROCESS_INFORMATION	pi		= {0};

	__try
	{
		// Need to set this for the structure
		si.cb = sizeof(STARTUPINFO);
	
		// Creates a new process and its primary thread.
		// The new process runs in the security context of the calling process.
		if(!CreateProcessW(
			lpProcPath,		// full path to process
			lpProcArgs,		// <process name> -arguments
			NULL,
			NULL,
			FALSE,
			CREATE_SUSPENDED,
			NULL,
			NULL,
			&si,
			&pi))
		{
			PRINT_ERROR_MSGA("Process could not be loaded.");
			__leave;
		}

		if(ResumeThread(pi.hThread) == (DWORD)-1)
		{
			PRINT_ERROR_MSGA("Could not resume process.");
			__leave;
		}

		// wait until process is initialized
		if(bWaitForInputIdle)
		{
			if(WaitForInputIdle(pi.hProcess, WII_WAITTIMEOUT) != 0)
			{
				PRINT_ERROR_MSGA("WaitForInputIdle failed.");
				__leave;
			}
		}

		bRet = EjectLibraryW(pi.dwProcessId, lpLibPath);
	}
	__finally
	{
		if(pi.hThread)
			CloseHandle(pi.hThread);

		if(pi.hProcess)
			CloseHandle(pi.hProcess);
	}

	return bRet;
}

BOOL 
EjectLibraryOnStartupA(
	LPCSTR lpLibPath,
	LPCSTR lpProcPath,
	LPSTR lpProcArgs,
	BOOL bWaitForInputIdle
	)
{
	BOOL bRet = FALSE;
	wchar_t *libpath = char_to_wchar_t(lpLibPath);
	wchar_t *procpath = char_to_wchar_t(lpProcPath);
	wchar_t *procargs = char_to_wchar_t(lpProcArgs);

	if(libpath == 0) return bRet;
	if(procpath == 0) return bRet;
	if(procargs == 0) return bRet;

	bRet = EjectLibraryOnStartupW(libpath, procpath, procargs, bWaitForInputIdle);

	if(libpath) free(libpath);
	if(procpath) free(procpath);
	if(procargs) free(procargs);
	
	return bRet;
}