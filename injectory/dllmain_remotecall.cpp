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
#include "injectory/process.hpp"
#include "injectory/memoryarea.hpp"

typedef BOOL(__stdcall *DLLMAIN)(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

struct DLLMAINCALL
{
	DLLMAIN fpDllMain;
	HMODULE hModule;
	DWORD ul_reason_for_call;
	LPVOID lpReserved;
};

BOOL __stdcall DllMainWrapper(struct DLLMAINCALL *parameter)
{
	return parameter->fpDllMain(parameter->hModule, parameter->ul_reason_for_call, parameter->lpReserved);
}
void DllMainWrapper_end(void)
{
}

void Process::remoteDllMainCall(LPVOID lpModuleEntry, HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	struct DLLMAINCALL dllMainCall = { (DLLMAIN)lpModuleEntry, hModule, ul_reason_for_call, lpReserved };
	SIZE_T DllMainWrapperSize = (SIZE_T)DllMainWrapper_end - (SIZE_T)DllMainWrapper; 

	MemoryArea param          = MemoryArea::alloc(*this, sizeof(struct DLLMAINCALL));
	MemoryArea dllCallWrapper = MemoryArea::alloc(*this, (SIZE_T)((DWORD_PTR)DllMainWrapper_end - (DWORD_PTR)DllMainWrapper));

	param.write((LPCVOID)&dllMainCall, sizeof(struct DLLMAINCALL));
	dllCallWrapper.write((LPCVOID)DllMainWrapper, DllMainWrapperSize);
	dllCallWrapper.flushInstructionCache(DllMainWrapperSize);

	runInHiddenThread((LPTHREAD_START_ROUTINE)dllCallWrapper.address(), param.address());
}
