#include "injectory/process.hpp"
#include "injectory/injector_helper.hpp"
#include "injectory/generic_injector.hpp"
#include "injectory/module.hpp"
#include <iostream>

using namespace std;

void Process::inject(const path& lib)
{
	bool suspended = false;
	LPVOID lpInjectedModule = 0;
	SIZE_T NumBytesWritten = 0;
	SIZE_T Memory = 0;
	DWORD loadLibraryThreadID = 0;
	DWORD dwExitCode = 0;
	WCHAR NtFileNameThis[MAX_PATH + 1] = { 0 };
	WCHAR NtMappedFileName[MAX_PATH + 1] = { 0 };
	MEMORY_BASIC_INFORMATION mem_basic_info = { 0 };

	try
	{
		Module kernel32dll(L"Kernel32");
		LPTHREAD_START_ROUTINE loadLibrary = (PTHREAD_START_ROUTINE)kernel32dll.getProcAddress("LoadLibraryW");

		Process proc = Process::open(id);
		proc.suspend();
		suspended = true;

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

		// flush instruction cache
		if (!FlushInstructionCache(proc.handle(), lpLibFileRemote.get(), LibPathLen))
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not flush instruction cache"));

		// Create a remote thread that calls LoadLibraryW
		boost::shared_ptr<void> loadLibraryThread(CreateRemoteThread(
			proc.handle(),
			0,
			0,
			loadLibrary,
			lpLibFileRemote.get(),
			0,
			&loadLibraryThreadID),
			CloseHandle);

		if (loadLibraryThread == 0)
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not create thread in remote process"));

		if (!SetThreadPriority(loadLibraryThread.get(), THREAD_PRIORITY_TIME_CRITICAL))
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not set thread priority"));

		HideThreadFromDebugger(loadLibraryThreadID);


		// Wait for the remote thread to terminate
		if (WaitForSingleObject(loadLibraryThread.get(), INJLIB_WAITTIMEOUT) == WAIT_FAILED)
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("WaitForSingleObject failed"));

		if (!GetExitCodeThread(loadLibraryThread.get(), &dwExitCode))
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not get thread exit code"));

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
				dwExitCode);
		}

		if (dwExitCode == 0 && lpInjectedModule == 0)
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("unknown error (LoadLibraryW)"));

		proc.resume();
	}
	catch (const boost::exception& e)
	{
		if (suspended)
			Process::open(id).resume();
		throw;
	}
}

Process Process::open(const pid_t& pid, bool inheritHandle, DWORD desiredAccess)
{
	Process proc(pid, OpenProcess(desiredAccess, inheritHandle, pid));

	if (!proc.handle())
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not get handle to process") << e_pid(pid));
	else
		return proc;
}

ProcessWithThread Process::launch(const path & application, const wstring & args)
{
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO			si = { 0 };
	si.cb = sizeof(STARTUPINFO); // needed
	wstring commandLine = application.wstring() + L" " + args;

	if (!CreateProcessW(application.c_str(), &commandLine[0], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("CreateProcess failed"));
	else
		return ProcessWithThread(pi.dwProcessId, pi.hProcess, Thread(pi.dwThreadId, pi.hThread));
}

void Process::suspend(bool _suspend) const
{
	typedef LONG(NTAPI* func)(HANDLE);
	func suspend_resume;
	Module ntDll(L"ntdll");

	if (_suspend)
		suspend_resume = (func)ntDll.getProcAddress("NtSuspendProcess");
	else
		suspend_resume = (func)ntDll.getProcAddress("NtResumeProcess");

	LONG ntStatus = (*suspend_resume)(handle());
	if (!NT_SUCCESS(ntStatus))
		BOOST_THROW_EXCEPTION(ex_suspend_resume_process() << e_nt_status(ntStatus));
}
