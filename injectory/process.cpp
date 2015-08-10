#include "injectory/process.hpp"
#include "injectory/injector_helper.hpp"
#include "injectory/generic_injector.hpp"
#include "injectory/module.hpp"
#include <iostream>
#include <process.h>

using namespace std;

Process Process::open(const pid_t& pid, bool inheritHandle, DWORD desiredAccess)
{
	Process proc(pid, OpenProcess(desiredAccess, inheritHandle, pid));
	if (!proc.handle())
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not get handle to process") << e_pid(pid));
	else
		return proc;
}

ProcessWithThread Process::launch(const path& app, const wstring& args,
	boost::optional<const vector<string>&> env,
	boost::optional<const wstring&> cwd,
	bool inheritHandles, DWORD creationFlags,
	SECURITY_ATTRIBUTES* processAttributes, SECURITY_ATTRIBUTES* threadAttributes,
	STARTUPINFOW* startupInfo)
{
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO			si = { 0 };
	si.cb = sizeof(STARTUPINFO); // needed
	wstring commandLine = app.wstring() + L" " + args;

	if (!CreateProcessW(app.c_str(), &commandLine[0], processAttributes, threadAttributes, inheritHandles, creationFlags, NULL, NULL, &si, &pi))
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("CreateProcess failed"));
	else
		return ProcessWithThread(pi.dwProcessId, pi.hProcess, Thread(pi.dwThreadId, pi.hThread));
}

void Process::suspend(bool _suspend) const
{
	typedef LONG(NTAPI* func)(HANDLE);
	func suspend_resume;
	Module ntDll("ntdll");

	if (_suspend)
		suspend_resume = (func)ntDll.getProcAddress("NtSuspendProcess");
	else
		suspend_resume = (func)ntDll.getProcAddress("NtResumeProcess");

	LONG ntStatus = (*suspend_resume)(handle());
	if (!NT_SUCCESS(ntStatus))
		BOOST_THROW_EXCEPTION(ex_suspend_resume_process() << e_nt_status(ntStatus));
}

void Process::inject(const path& lib, const bool& verbose)
{
	LPVOID lpInjectedModule = 0;
	SIZE_T NumBytesWritten = 0;
	SIZE_T Memory = 0;
	DWORD loadLibraryThreadID = 0;
	WCHAR NtFileNameThis[MAX_PATH + 1] = { 0 };
	WCHAR NtMappedFileName[MAX_PATH + 1] = { 0 };
	MEMORY_BASIC_INFORMATION mem_basic_info = { 0 };

	Module kernel32dll("kernel32");
	LPTHREAD_START_ROUTINE loadLibrary = (PTHREAD_START_ROUTINE)kernel32dll.getProcAddress("LoadLibraryW");

	Process proc = Process::open(id);
	proc.suspend();
	proc.tryResumeOnDestruction();

	if (!GetFileNameNtW(lib.c_str(), NtFileNameThis, MAX_PATH))
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not get the NT namespace path"));

	if (ModuleInjectedW(proc.handle(), NtFileNameThis) != 0)
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("module already in process") << e_file_path(lib) << e_pid(id));

	// Calculate the number of bytes needed for the DLL's pathname
	SIZE_T  LibPathLen = (wcslen(lib.c_str()) + 1) * sizeof(wchar_t);

	// Allocate space in the remote process for the pathname
	shared_ptr<void> lpLibFileRemote(VirtualAllocEx(
		proc.handle(),
		NULL,
		LibPathLen,
		MEM_COMMIT,
		PAGE_READWRITE),
		bind(VirtualFreeEx, proc.handle(), std::placeholders::_1, 0, MEM_RELEASE));

	if (!lpLibFileRemote)
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not allocate memory in remote process"));

	if (!WriteProcessMemory(proc.handle(), lpLibFileRemote.get(), (LPCVOID)(lib.c_str()), LibPathLen, &NumBytesWritten) || NumBytesWritten != LibPathLen)
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not write to memory in remote process"));

	if (!FlushInstructionCache(proc.handle(), lpLibFileRemote.get(), LibPathLen))
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not flush instruction cache"));

	Thread loadLibraryThread = Thread::createRemote(proc, 0, 0, loadLibrary, lpLibFileRemote.get(), 0);
	loadLibraryThread.setPriority(THREAD_PRIORITY_TIME_CRITICAL);
	loadLibraryThread.hideFromDebugger();
	DWORD exitCode = loadLibraryThread.waitForTermination();

	lpInjectedModule = ModuleInjectedW(proc.handle(), NtFileNameThis);
	if (lpInjectedModule != 0)
	{
		IMAGE_NT_HEADERS nt_header = { 0 };
		IMAGE_DOS_HEADER dos_header = { 0 };
		SIZE_T NumBytesRead = 0;
		LPVOID lpNtHeaderAddress = 0;

		if (!ReadProcessMemory(proc.handle(), lpInjectedModule, &dos_header, sizeof(IMAGE_DOS_HEADER), &NumBytesRead) ||
			NumBytesRead != sizeof(IMAGE_DOS_HEADER))
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not read memory in remote process"));

		lpNtHeaderAddress = (LPVOID)((DWORD_PTR)lpInjectedModule + dos_header.e_lfanew);
		if (!ReadProcessMemory(proc.handle(), lpNtHeaderAddress, &nt_header, sizeof(IMAGE_NT_HEADERS), &NumBytesRead) ||
			NumBytesRead != sizeof(IMAGE_NT_HEADERS))
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not read memory in remote process"));

		if (verbose)
		{
			wprintf(
				L"Successfully injected (%s | PID: %d):\n\n"
				L"  AllocationBase: 0x%p\n"
				L"  EntryPoint:     0x%p\n"
				L"  SizeOfImage:      %.1f kB\n"
				L"  CheckSum:       0x%08x\n"
				L"  ExitCodeThread: 0x%08x\n",
				NtFileNameThis,
				id,
				lpInjectedModule,
				(LPVOID)((DWORD_PTR)lpInjectedModule + nt_header.OptionalHeader.AddressOfEntryPoint),
				nt_header.OptionalHeader.SizeOfImage / 1024.0,
				nt_header.OptionalHeader.CheckSum,
				exitCode);
		}
	}
	else if (exitCode == 0 && lpInjectedModule == 0)
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("unknown error (LoadLibraryW)"));
}

bool Process::is64bit() const
{
	// Wenn es ein 64bit-System ist, sind alle Prozesse, für die IsWow64Process
	// TRUE zurückliefert, 32bit-Prozesse, alle anderen 64bit-Prozesse.
	// Unter einem 32bit-Windows ist sowieso alles 32bit.

	SYSTEM_INFO siSysInfo = { 0 };
	typedef BOOL(WINAPI *func)(HANDLE, PBOOL);
	func _IsWow64Process = 0;

	MyGetSystemInfo(&siSysInfo);

	if (siSysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) // x64 (AMD or Intel)
	{
		BOOL bIsWow64 = FALSE;
		Module kernel32dll("kernel32");

		_IsWow64Process = (func)kernel32dll.getProcAddress("IsWow64Process");

		Process proc = Process::open(id, false, PROCESS_QUERY_INFORMATION);

		if (!_IsWow64Process(proc.handle(), &bIsWow64))
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("IsWow64Process failed"));

		return bIsWow64 ? 0 : 1;
	}
	else if (siSysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) // x86
		return false;
	else
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("failed to determine whether x86 or x64") << e_pid(id));
}
