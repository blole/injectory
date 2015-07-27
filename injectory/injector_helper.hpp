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
#pragma once
#include <stdio.h>

#include <Windows.h>
#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")

#include "injectory/common.hpp"

FARPROC
GetRemoteProcAddress(
	HANDLE hProcess,
	HMODULE hRemoteModule,
	LPCSTR lpProcName
	);

BOOL
EnablePrivilegeW(
	LPCWSTR	lpPrivilegeName,
	BOOL bEnable
	);

void SuspendResumeProcess(const pid_t& pid, bool bResumeProcess);
void HideThreadFromDebugger(const tid_t& tid);

BOOL
GetFileNameNtW(
	LPCWSTR lpFileName,
	LPWSTR lpFileNameNt,
	DWORD nSize
	);

LPVOID
ModuleInjectedW(
	HANDLE hProcess,
	LPCWSTR lpLibPathNt
	);

VOID
ListModules(
	DWORD dwProcessId
	);

void
__stdcall
MyGetSystemInfo(
	LPSYSTEM_INFO lpSystemInfo
	);

INT
IsProcess64(
	DWORD dwProcessId
	);

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

enum MY_THREAD_INFORMATION_CLASS
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger
};
