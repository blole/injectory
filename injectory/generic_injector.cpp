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

void InjectLibrary(const pid_t& pid, const path& lib)
{
	using std::placeholders::_1;

	BOOL bRet = FALSE;
	BOOL bProcSuspend = FALSE;
	LPVOID lpInjectedModule = 0;
	HMODULE hKernel32Dll = 0;
	SIZE_T LibPathLen = 0;
	SIZE_T NumBytesWritten = 0;
	SIZE_T Memory = 0;
	DWORD dwThreadId = 0;
	DWORD dwExitCode = 0;
	LPTHREAD_START_ROUTINE lpLoadLibraryW = 0;
	WCHAR NtFileNameThis[MAX_PATH + 1] = {0};
	WCHAR NtMappedFileName[MAX_PATH + 1] = {0};
	MEMORY_BASIC_INFORMATION mem_basic_info	= {0};

	try
	{
		hKernel32Dll = GetModuleHandleW(L"Kernel32");
		if(!hKernel32Dll)
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not get handle to Kernel32"));

		lpLoadLibraryW = (PTHREAD_START_ROUTINE)GetProcAddress(hKernel32Dll, "LoadLibraryW");
		if(!lpLoadLibraryW)
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not get the address of LoadLibraryW"));

		// Get a handle for the target process.
		boost::shared_ptr<void> hProcess(OpenProcess(
			PROCESS_QUERY_INFORMATION	|	// Required by Alpha
			PROCESS_CREATE_THREAD		|	// For CreateRemoteThread
			PROCESS_VM_OPERATION		|	// For VirtualAllocEx/VirtualFreeEx
			PROCESS_VM_WRITE			|	// For WriteProcessMemory
			PROCESS_VM_READ,
			FALSE, 
			pid),
			CloseHandle);

		if(!hProcess.get())
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not get handle to process") << e_pid(pid));

		// suspend process
		if(!(bProcSuspend = SuspendResumeProcess(pid, FALSE)))
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not suspend process"));

		if(!GetFileNameNtW(lib.c_str(), NtFileNameThis, MAX_PATH))
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not get the NT namespace path"));

		if(ModuleInjectedW(hProcess.get(), NtFileNameThis) != 0)
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("module already in process") << e_file_path(lib) << e_pid(pid));

		// Calculate the number of bytes needed for the DLL's pathname
		LibPathLen = (wcslen(lib.c_str()) + 1) * sizeof(wchar_t);

		// Allocate space in the remote process for the pathname
		shared_ptr<void> lpLibFileRemote(VirtualAllocEx(
			hProcess.get(),
			NULL, 
			LibPathLen, 
			MEM_COMMIT, 
			PAGE_READWRITE),
			bind(VirtualFreeEx, hProcess.get(), _1, 0, MEM_RELEASE));

		if(!lpLibFileRemote)
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not allocate memory in remote process"));

		if(!WriteProcessMemory(hProcess.get(), lpLibFileRemote.get(), (LPCVOID)(lib.c_str()), LibPathLen, &NumBytesWritten) || NumBytesWritten != LibPathLen)
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not write to memory in remote process"));

		// flush instruction cache
		if(!FlushInstructionCache(hProcess.get(), lpLibFileRemote.get(), LibPathLen))
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not flush instruction cache"));

		// Create a remote thread that calls LoadLibraryW
		boost::shared_ptr<void> hThread(CreateRemoteThread(
			hProcess.get(),
			0,
			0,
			lpLoadLibraryW,
			lpLibFileRemote.get(),
			0,
			&dwThreadId),
			CloseHandle);

		if(hThread == 0)
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not create thread in remote process"));

		if(!SetThreadPriority(hThread.get(), THREAD_PRIORITY_TIME_CRITICAL))
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not set thread priority"));

		HideThreadFromDebugger(dwThreadId);
			

		// Wait for the remote thread to terminate
		if(WaitForSingleObject(hThread.get(), INJLIB_WAITTIMEOUT) == WAIT_FAILED)
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("WaitForSingleObject failed"));

		if(!GetExitCodeThread(hThread.get(), &dwExitCode))
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not get thread exit code"));

		lpInjectedModule = ModuleInjectedW(hProcess.get(), NtFileNameThis);
		if(lpInjectedModule != 0)
		{
			IMAGE_NT_HEADERS nt_header = {0};
			IMAGE_DOS_HEADER dos_header = {0};
			SIZE_T NumBytesRead = 0;
			LPVOID lpNtHeaderAddress = 0;

			if(!ReadProcessMemory(hProcess.get(), lpInjectedModule, &dos_header, sizeof(IMAGE_DOS_HEADER), &NumBytesRead) ||
					NumBytesRead != sizeof(IMAGE_DOS_HEADER))
				BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not read memory in remote process"));

			lpNtHeaderAddress = (LPVOID)( (DWORD_PTR)lpInjectedModule + dos_header.e_lfanew );
			if(!ReadProcessMemory(hProcess.get(), lpNtHeaderAddress, &nt_header, sizeof(IMAGE_NT_HEADERS), &NumBytesRead) ||
					NumBytesRead != sizeof(IMAGE_NT_HEADERS))
				BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not read memory in remote process"));

			wprintf(
				L"Successfully injected (%s | PID: %d):\n\n"
				L"  AllocationBase: 0x%p\n"
				L"  EntryPoint:     0x%p\n"
				L"  SizeOfImage:      %.1f kB\n"
				L"  CheckSum:       0x%08x\n"
				L"  ExitCodeThread: 0x%08x\n",
				NtFileNameThis,
				pid,
				lpInjectedModule,
				(LPVOID)((DWORD_PTR)lpInjectedModule + nt_header.OptionalHeader.AddressOfEntryPoint),
				nt_header.OptionalHeader.SizeOfImage/1024.0,
				nt_header.OptionalHeader.CheckSum,
				dwExitCode);
		}

		if(dwExitCode == 0 && lpInjectedModule == 0)
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("unknown error (LoadLibraryW)"));
	}
	catch (const boost::exception& e)
	{
		e << e_text("injection failed");

		// resume process
		if (bProcSuspend && !SuspendResumeProcess(pid, TRUE))
			e << e_text("could not resume process");

		throw;
	}

	// resume process
	if (bProcSuspend && !SuspendResumeProcess(pid, TRUE))
		BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not resume process"));
}

BOOL
EjectLibrary(
	DWORD dwProcessId,
	LPVOID lpModule
	)
{
	BOOL bRet = FALSE;
	BOOL bProcSuspend = FALSE;
	HANDLE hProcess = 0;
	HANDLE hThread = 0;
	HMODULE hKernel32Dll = 0;
	LPTHREAD_START_ROUTINE lpFreeLibrary = 0;
	DWORD dwThreadId = 0;
	DWORD dwExitCode = 0;

	__try
	{
		hKernel32Dll = GetModuleHandleW(L"Kernel32");
		if(!hKernel32Dll)
		{
			PRINT_ERROR_MSGA("Could not get handle to Kernel32.");
			__leave;
		}

		lpFreeLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(hKernel32Dll, "FreeLibrary");
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
			dwProcessId);
		if(!hProcess)
		{
			PRINT_ERROR_MSGA("Could not get handle to process (PID: %d).", dwProcessId);
			__leave;
		}

		// suspend process
		if(!(bProcSuspend = SuspendResumeProcess(dwProcessId, FALSE)))
		{
			PRINT_ERROR_MSGA("Could not suspend process.");
			__leave;
		}

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
			dwProcessId,
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

		// resume process
		if(bProcSuspend)
		{
			if(!SuspendResumeProcess(dwProcessId, TRUE))
			{
				PRINT_ERROR_MSGA("Could not resume process.");
			}
		}
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

pid_t InjectLibraryOnStartup(const path& lib, const path& application, const wstring& applicationArgs, bool waitForInputIdle)
{
	try
	{
		STARTUPINFO			si = { 0 };
		PROCESS_INFORMATION	pi = { 0 };
		si.cb = sizeof(STARTUPINFO);	// need to set this for the structure
		pid_t& pid = pi.dwProcessId;

		wstring commandLine = application.wstring() + L" " + applicationArgs;

		// Creates a new process and its primary thread.
		// The new process runs in the security context of the calling process.
		BOOL success = CreateProcessW(
			application.c_str(),	// full path to process
			&commandLine[0],		// <process name> <arguments>
			NULL,
			NULL,
			FALSE,
			CREATE_SUSPENDED,
			NULL,
			NULL,
			&si,
			&pi);

		boost::shared_ptr<void>  hThread(pi.hThread, CloseHandle);
		boost::shared_ptr<void> hProcess(pi.hProcess, CloseHandle);

		if (!success)
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("process could not be loaded"));

		if (ResumeThread(pi.hThread) == (DWORD)-1)
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("could not resume process"));

		// wait until process is initialized
		if (waitForInputIdle && WaitForInputIdle(pi.hProcess, WII_WAITTIMEOUT) != 0)
			BOOST_THROW_EXCEPTION (ex_injection() << e_text("WaitForInputIdle failed"));

		InjectLibrary(pid, lib);
		return pid;
	}
	catch (const boost::exception& e)
	{
		e << e_text("injection failed");
		throw;
	}
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
		{
			CloseHandle(pi.hThread);
		}

		if(pi.hProcess)
		{
			CloseHandle(pi.hProcess);
		}
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