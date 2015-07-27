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
#include "injectory/dllmain_remotecall.hpp"

BOOL __stdcall DllMainWrapper(struct DLLMAINCALL *parameter)
{
	return parameter->fpDllMain(parameter->hModule, parameter->ul_reason_for_call, parameter->lpReserved);
}
void DllMainWrapper_end(void)
{
}

BOOL RemoteDllMainCall(HANDLE hProcess, LPVOID lpModuleEntry, HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	BOOL bRet = FALSE;
	struct DLLMAINCALL dllMainCall = { (DLLMAIN)lpModuleEntry, hModule, ul_reason_for_call, lpReserved };
	SIZE_T DllMainWrapperSize = (SIZE_T)DllMainWrapper_end - (SIZE_T)DllMainWrapper; 
	LPVOID lpParam = 0;
	LPVOID lpDllCallWrapper = 0;
	HANDLE hThread = 0;
	DWORD dwThreadId = 0;
	DWORD dwExitCode = 0;

	__try
	{
		lpParam = VirtualAllocEx(
			hProcess,
			NULL, 
			sizeof(struct DLLMAINCALL), 
			MEM_COMMIT | MEM_RESERVE, 
			PAGE_EXECUTE_READWRITE);
		if(!lpParam)
		{
			PRINT_ERROR_MSGA("Could not allocate memory in remote process.");
			__leave;
		}

		lpDllCallWrapper = VirtualAllocEx(
			hProcess,
			NULL, 
			(SIZE_T)( (DWORD_PTR)DllMainWrapper_end - (DWORD_PTR)DllMainWrapper ),
			MEM_COMMIT | MEM_RESERVE, 
			PAGE_EXECUTE_READWRITE);
		if(!lpDllCallWrapper)
		{
			PRINT_ERROR_MSGA("Could not allocate memory in remote process.");
			__leave;
		}

		{
			SIZE_T NumBytesWritten = 0;
			if(!WriteProcessMemory(hProcess, lpParam, (LPCVOID)&dllMainCall, sizeof(struct DLLMAINCALL), &NumBytesWritten) ||
				NumBytesWritten != sizeof(struct DLLMAINCALL))
			{
				PRINT_ERROR_MSGA("Could not write to memory in remote process.");
				__leave;
			}
			if(!WriteProcessMemory(hProcess, lpDllCallWrapper, (LPCVOID)DllMainWrapper, DllMainWrapperSize, &NumBytesWritten) ||
				NumBytesWritten != DllMainWrapperSize)
			{
				PRINT_ERROR_MSGA("Could not write to memory in remote process.");
				__leave;
			}

			// flush instruction cache
			if(!FlushInstructionCache(hProcess, lpDllCallWrapper, DllMainWrapperSize))
			{
				PRINT_ERROR_MSGA("Could not flush instruction cache.");
				__leave;
			}
		}

		hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)lpDllCallWrapper, lpParam, 0, &dwThreadId);
		if(!hThread)
		{
			PRINT_ERROR_MSGA("Could not create thread in remote process.");
			__leave;
		}

		if(!SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL))
		{
			PRINT_ERROR_MSGA("Could not set thread priority.");
			__leave;
		}
		
		// Wait for the remote thread to terminate
		if(WaitForSingleObject(hThread, 5000) == WAIT_FAILED)
		{
			PRINT_ERROR_MSGA("WaitForSingleObject failed.");
			__leave;
		}

		// Get thread exit code
		if(!GetExitCodeThread(hThread, &dwExitCode))
		{
			PRINT_ERROR_MSGA("Could not get thread exit code.");
			__leave;
		}
		
		bRet = TRUE;
	}
	__finally
	{
		if(lpParam)
		{
			VirtualFreeEx(hProcess, lpParam, 0, MEM_RELEASE);
		}

		if(lpDllCallWrapper)
		{
			VirtualFreeEx(hProcess, lpDllCallWrapper, 0, MEM_RELEASE);
		}
	}

	return bRet;
}