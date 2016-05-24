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
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("OpenProcess") << e_text("could not get handle to process") << e_pid(pid) << e_last_error(errcode));
	}
	else
		return proc;
}

ProcessWithThread Process::launch(const fs::path& app, const wstring& args,
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
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("CreateProcess") << e_last_error(errcode) << e_file(app));
	}
	else
		return ProcessWithThread(Process(pi.dwProcessId, pi.hProcess), Thread(pi.dwThreadId, pi.hThread));
}

Process Process::findByWindow(wstring className, wstring windowName)
{
	HWND hwnd = FindWindowW(className.empty() ? nullptr : className.c_str(), windowName.empty() ? nullptr : windowName.c_str());
	if (!hwnd)
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("FindWindow") << e_text("could not find window class:'" + to_string(className) + "' title:'" + to_string(windowName) + "'") << e_last_error(errcode));
	}

	pid_t pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid == 0)
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("GetWindowThreadProcessId") << e_text("could not get process id for window class:'" + to_string(className) + "' title:'" + to_string(windowName) + "'"));

	return Process::open(pid);
}

Process Process::findByExeName(wstring name)
{
	WinHandle procSnap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), CloseHandle);

	if (procSnap.handle() == INVALID_HANDLE_VALUE)
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("CreateToolhelp32Snapshot") << e_text("could not get process snapshot for '" + to_string(name) + "'") << e_last_error(errcode));
	}

	PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
	if (Process32FirstW(procSnap.handle(), &pe32))
	{
		do
		{
			if (boost::iequals(name, pe32.szExeFile))
				return Process::open(pe32.th32ProcessID);
		} while (Process32NextW(procSnap.handle(), &pe32));
	}

	BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not get find process '" + to_string(name) + "'"));
}

void Process::suspend(bool suspend_) const
{
	if (suspend_)
		Module::ntdll().ntSuspendProcess(*this);
	else
		Module::ntdll().ntResumeProcess(*this);
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

MemoryArea Process::memory(void* address, SIZE_T size)
{
	return MemoryArea(*this, address, size, false);
}

MemoryArea Process::alloc(SIZE_T size, bool freeOnDestruction, DWORD allocationType, DWORD protect, void* addressHint)
{
	return MemoryArea::alloc(*this, size, freeOnDestruction, allocationType, protect, addressHint);
}

Module Process::inject(const Library& lib, const bool& verbose)
{
	if (isInjected(lib))
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("library already in process") << e_library(lib.path()) << e_process(*this));

	// copy the pathname to the remote process
	SIZE_T libPathLen = (lib.path().wstring().size() + 1) * sizeof(wchar_t);
	MemoryArea libFileRemote = alloc(libPathLen, true, MEM_COMMIT, PAGE_READWRITE);
	libFileRemote.write((void*)(lib.path().c_str()));

	DWORD exitCode = runInHiddenThread(loadLibraryW, libFileRemote.address());
	PTHREAD_START_ROUTINE loadLibraryW = (PTHREAD_START_ROUTINE)Module::kernel32().getProcAddress("LoadLibraryW");

	if (Module module = isInjected(lib))
	{
		IMAGE_DOS_HEADER dos_header = memory<IMAGE_DOS_HEADER>(module.handle());
		void* nt_header_address = (void*)((DWORD_PTR)module.handle() + dos_header.e_lfanew);
		IMAGE_NT_HEADERS nt_header = memory<IMAGE_NT_HEADERS>(nt_header_address);

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

DWORD Process::runInHiddenThread(PTHREAD_START_ROUTINE startAddress, LPVOID parameter)
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
		return Module::kernel32().isWow64Process(*this);
	else if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) // x86
		return false;
	else
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("failed to determine whether x86 or x64") << e_process(*this));
}

Module Process::isInjected(const Library& lib)
{
	MEMORY_BASIC_INFORMATION mem_basic_info = { 0 };
	SYSTEM_INFO sys_info = getSystemInfo();

	for (SIZE_T mem = 0; mem < (SIZE_T)sys_info.lpMaximumApplicationAddress; mem += mem_basic_info.RegionSize)
	{
		mem_basic_info = memBasicInfo((const void*)mem);

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
		mem_basic_info = memBasicInfo((const void*)mem);

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
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("failed to find injected library") << e_process(*this) << e_library(lib.path()));
}
Module Process::getInjected(HMODULE hmodule)
{
	if (Module module = isInjected(hmodule))
		return module;
	else
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("failed to find module handle") << e_process(*this));
}

Module Process::map(const File& file)
{
	WinHandle fileMap(CreateFileMappingW(file.handle(), nullptr, PAGE_READONLY, 0, 1, nullptr), CloseHandle);
	if (!fileMap)
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("CreateFileMapping") << e_file(file.path()) << e_last_error(errcode));
	}

	Module module((HMODULE)MapViewOfFile(fileMap.handle(), FILE_MAP_READ, 0, 0, 1), Process::current, UnmapViewOfFile);
	if (!module)
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("MapViewOfFile") << e_file(file.path()) << e_last_error(errcode));
	}
	return module;
}

void Process::listModules()
{
	MEMORY_BASIC_INFORMATION mem_basic_info = { 0 };
	SYSTEM_INFO sys_info = getSystemInfo();

	cout << "BASE\t\t SIZE\t\t  MODULE" << endl;

	for (SIZE_T mem = 0; mem < (SIZE_T)sys_info.lpMaximumApplicationAddress; mem += mem_basic_info.RegionSize)
	{
		void* ab = mem_basic_info.AllocationBase;
		mem_basic_info = memBasicInfo((void*)mem);
		if (ab == mem_basic_info.AllocationBase)
			continue;

		wstring ntMappedFileName = getInjected((HMODULE)mem_basic_info.AllocationBase).mappedFilename(false);

		if (!ntMappedFileName.empty())
		{
			IMAGE_DOS_HEADER dos_header = memory<IMAGE_DOS_HEADER>(mem_basic_info.AllocationBase);
			void* nt_header_address = (void*)((DWORD_PTR)mem_basic_info.AllocationBase + dos_header.e_lfanew);
			IMAGE_NT_HEADERS nt_header = memory<IMAGE_NT_HEADERS>(nt_header_address);
			cout << format("0x%p, %.1f kB, ") % mem_basic_info.AllocationBase % (nt_header.OptionalHeader.SizeOfImage / 1024.0) << to_string(ntMappedFileName) << endl;
		}
	}
}
