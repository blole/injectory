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
#include "injectory/process.hpp"
#include "injectory/thread.hpp"
#include "injectory/module.hpp"

#include <functional>
using namespace std;

void EjectLibrary(DWORD pid, LPVOID module)
{
	LPTHREAD_START_ROUTINE lpFreeLibrary = (PTHREAD_START_ROUTINE)Module::kernel32.getProcAddress("FreeLibrary");

	Process proc = Process::open(pid);
	proc.suspend();
	proc.tryResumeOnDestruction();

	Thread thread = proc.createRemoteThread(lpFreeLibrary, module);
	thread.setPriority(THREAD_PRIORITY_TIME_CRITICAL);
	thread.hideFromDebugger();
	DWORD exitCode = thread.waitForTermination();

	if(!exitCode) // - invalid PE header?
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("call to FreeLibrary in remote process failed"));

	printf("Successfully ejected (0x%p | PID: %d):\n\n  ExitCodeThread: 0x%08x\n",
		module, pid, exitCode);
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
						EjectLibrary(dwProcessId, mem_basic_info.AllocationBase);
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