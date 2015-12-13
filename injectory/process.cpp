#include "injectory/process.hpp"
#include "injectory/memoryarea.hpp"
#include <boost/algorithm/string.hpp>
#include "injectory/module.hpp"
#include "injectory/library.hpp"
#include "injectory/file.hpp"
#include <TlHelp32.h>

Process Process::current(GetCurrentProcessId(), GetCurrentProcess());

Process Process::open(const pid_t& pid, bool inheritHandle, DWORD desiredAccess)
{
	Process proc(pid, OpenProcess(desiredAccess, inheritHandle, pid));
	if (!proc.handle())
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not get handle to process") << e_pid(pid));
	else
		return proc;
}

ProcessWithThread Process::launch(const path& app, const wstring& args,
	optional<const vector<string>&> env,
	optional<const wstring&> cwd,
	bool inheritHandles, DWORD creationFlags,
	SECURITY_ATTRIBUTES* processAttributes, SECURITY_ATTRIBUTES* threadAttributes,
	STARTUPINFOW startupInfo)
{
	startupInfo.cb = sizeof(STARTUPINFOW); // needed
	PROCESS_INFORMATION pi = {};
	wstring commandLine = app.wstring() + L" " + args;

	if (!CreateProcessW(app.c_str(), &commandLine[0], processAttributes, threadAttributes, inheritHandles,
			creationFlags, nullptr, nullptr, &startupInfo, &pi))
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("CreateProcess failed"));
	else
		return ProcessWithThread(Process(pi.dwProcessId, pi.hProcess), Thread(pi.dwThreadId, pi.hThread));
}

void Process::suspend(bool _suspend) const
{
	string funcName = _suspend ? "NtSuspendProcess" : "NtResumeProcess";
	auto func = Module::ntdll().getProcAddress<LONG, HANDLE>(funcName);
	LONG ntStatus = func(handle());
	if (!NT_SUCCESS(ntStatus))
		BOOST_THROW_EXCEPTION(ex_suspend_resume_process() << e_nt_status(ntStatus));
}

void Process::suspendAllThreads(bool _suspend) const
{
	for (Thread& thread : threads(false, THREAD_SUSPEND_RESUME))
		thread.suspend(_suspend);
}

vector<Thread> Process::threads(bool inheritHandle, DWORD desiredAccess) const
{
	vector<Thread> threads_;
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, id());
	if (h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do
			{
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
				{
					if (te.th32OwnerProcessID == id())
					{
						try
						{
							threads_.push_back(Thread::open(te.th32ThreadID, inheritHandle, desiredAccess));
						}
						catch (...)
						{
							// if the process is running, threads may have terminated
						}
					}
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}
	return threads_;
}

MemoryArea Process::alloc(SIZE_T size, bool freeOnDestruction, DWORD allocationType, DWORD protect, LPVOID address)
{
	return MemoryArea::alloc(*this, size, freeOnDestruction, allocationType, protect, address);
}

Module Process::inject(const Library& lib, const bool& verbose)
{
	if (isInjected(lib))
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("library already in process") << e_library(lib) << e_pid(id()));

	// copy the pathname to the remote process
	SIZE_T libPathLen = (lib.path.wstring().size() + 1) * sizeof(wchar_t);
	MemoryArea libFileRemote = alloc(libPathLen, true, MEM_COMMIT, PAGE_READWRITE);
	libFileRemote.write((LPCVOID)(lib.path.c_str()), libPathLen);

	LPTHREAD_START_ROUTINE loadLibraryW = (PTHREAD_START_ROUTINE)Module::kernel32().getProcAddress("LoadLibraryW");
	DWORD exitCode = runInHiddenThread(loadLibraryW, libFileRemote.address());

	if (Module module = isInjected(lib))
	{
		IMAGE_NT_HEADERS nt_header = { 0 };
		IMAGE_DOS_HEADER dos_header = { 0 };
		SIZE_T NumBytesRead = 0;

		if (!ReadProcessMemory(handle(), module.handle(), &dos_header, sizeof(IMAGE_DOS_HEADER), &NumBytesRead) ||
			NumBytesRead != sizeof(IMAGE_DOS_HEADER))
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not read memory in remote process"));

		LPVOID lpNtHeaderAddress = (LPVOID)((DWORD_PTR)module.handle() + dos_header.e_lfanew);
		if (!ReadProcessMemory(handle(), lpNtHeaderAddress, &nt_header, sizeof(IMAGE_NT_HEADERS), &NumBytesRead) ||
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
				lib.ntFilename().c_str(),
				id(),
				module.handle(),
				(LPVOID)((DWORD_PTR)module.handle() + nt_header.OptionalHeader.AddressOfEntryPoint),
				nt_header.OptionalHeader.SizeOfImage / 1024.0,
				nt_header.OptionalHeader.CheckSum,
				exitCode);
		}
		return module;
	}
	else
		return Module(); //injected successfully, but module access denied TODO: really? does this happen?
}

DWORD Process::runInHiddenThread(LPTHREAD_START_ROUTINE startAddress, LPVOID parameter)
{
	Thread thread = createRemoteThread(startAddress, parameter, CREATE_SUSPENDED);
	thread.setPriority(THREAD_PRIORITY_TIME_CRITICAL);
	thread.hideFromDebugger();
	thread.resume();
	DWORD exitCode = thread.waitForTermination();
	if (!exitCode)
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("call to function in remote process failed"));
	return exitCode;
}

bool Process::is64bit() const
{
	SYSTEM_INFO systemInfo = getNativeSystemInfo();

	if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) // x64
	{
		// In 64bit systems, IsWow64Process returns true for 32 bit processes.

		BOOL isWow64 = false;

		auto isWow64Process = Module::kernel32().getProcAddress<BOOL, HANDLE, PBOOL>("IsWow64Process");
		if (!isWow64Process(handle(), &isWow64))
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("IsWow64Process failed"));

		return !isWow64;
	}
	else if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) // x86
		return false;
	else
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("failed to determine whether x86 or x64") << e_pid(id()));
}

Module Process::isInjected(const Library& lib)
{
	MEMORY_BASIC_INFORMATION mem_basic_info = { 0 };
	SYSTEM_INFO sys_info = getSystemInfo();

	for (SIZE_T mem = 0; mem < (SIZE_T)sys_info.lpMaximumApplicationAddress; mem += mem_basic_info.RegionSize)
	{
		mem_basic_info = memBasicInfo((LPCVOID)mem);

		if ((mem_basic_info.AllocationProtect & PAGE_EXECUTE_WRITECOPY) &&
			(mem_basic_info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
				PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
		{
			Module module((HMODULE)mem_basic_info.AllocationBase, *this);
			if (boost::iequals(module.mappedFilename(*this), lib.ntFilename()))
				return module;
		}
	}

	return Module(); // access denied or not found
}

Module Process::isInjected(HMODULE hmodule)
{
	MEMORY_BASIC_INFORMATION mem_basic_info = { 0 };
	SYSTEM_INFO sys_info = getSystemInfo();

	for (SIZE_T mem = 0; mem < (SIZE_T)sys_info.lpMaximumApplicationAddress; mem += mem_basic_info.RegionSize)
	{
		mem_basic_info = memBasicInfo((LPCVOID)mem);

		if ((mem_basic_info.AllocationProtect & PAGE_EXECUTE_WRITECOPY) &&
			(mem_basic_info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
				PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
		{
			if ((HMODULE)mem_basic_info.AllocationBase == hmodule)
				return Module(hmodule, *this);
		}
	}

	return Module(); // access denied or not found
}

Module Process::getInjected(const Library& lib)
{
	if (Module module = isInjected(lib))
		return module;
	else
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("failed to find injected library") << e_pid(id()) << e_library(lib));
}
Module Process::getInjected(HMODULE hmodule)
{
	if (Module module = isInjected(hmodule))
		return module;
	else
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("failed to find module handle") << e_pid(id()));
}

Module Process::map(const File& file)
{
	WinHandle fileMap(CreateFileMappingW(file.handle(), nullptr, PAGE_READONLY, 0, 1, nullptr), CloseHandle);
	if (!fileMap)
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("CreateFileMappingW(" + file.path().string() + ") failed"));

	Module module((HMODULE)MapViewOfFile(fileMap.handle(), FILE_MAP_READ, 0, 0, 1), Process::current, UnmapViewOfFile);
	if (!module)
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("MapViewOfFile() failed"));
	return module;
}

void Process::listModules()
{
	MEMORY_BASIC_INFORMATION mem_basic_info = { 0 };
	SYSTEM_INFO sys_info = getSystemInfo();

	printf("BASE\t\t SIZE\t\t  MODULE\n\n");

	for (SIZE_T mem = 0; mem < (SIZE_T)sys_info.lpMaximumApplicationAddress; mem += mem_basic_info.RegionSize)
	{
		PVOID ab = mem_basic_info.AllocationBase;
		mem_basic_info = memBasicInfo((LPCVOID)mem);
		if (ab == mem_basic_info.AllocationBase)
			continue;

		wstring ntMappedFileName = getInjected((HMODULE)mem_basic_info.AllocationBase).mappedFilename(false);

		if (!ntMappedFileName.empty())
		{
			IMAGE_NT_HEADERS nt_header = { 0 };
			IMAGE_DOS_HEADER dos_header = { 0 };
			SIZE_T NumBytesRead = 0;
			LPVOID lpNtHeaderAddress = 0;
			//WCHAR *pModuleName = (WCHAR)0;

			//pModuleName = wcsrchr(ntMappedFileName, '\\');
			//if(!pModuleName)
			//{
			//	return;
			//}
			//++pModuleName;

			if (ReadProcessMemory(handle(), mem_basic_info.AllocationBase, &dos_header,
				sizeof(IMAGE_DOS_HEADER), &NumBytesRead) &&
				NumBytesRead == sizeof(IMAGE_DOS_HEADER))
			{
				lpNtHeaderAddress = (LPVOID)((DWORD_PTR)mem_basic_info.AllocationBase +
					dos_header.e_lfanew);

				if (ReadProcessMemory(handle(), lpNtHeaderAddress, &nt_header,
					sizeof(IMAGE_NT_HEADERS), &NumBytesRead) &&
					NumBytesRead == sizeof(IMAGE_NT_HEADERS))
				{
					wprintf(L"0x%p, %.1f kB, %s\n",
						mem_basic_info.AllocationBase,
						nt_header.OptionalHeader.SizeOfImage / 1024.0,
						ntMappedFileName.c_str());
				}
			}
		}
	}
}
