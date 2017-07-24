#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injectory/thread.hpp"
#include "injectory/winhandle.hpp"
#include "injectory/environment.hpp"
#include <boost/interprocess/mapped_region.hpp>
#include <winnt.h>
#include <Psapi.h>

class Library;
class File;
template<typename>
class MemoryAreaT;
class MemoryArea;
struct ProcessWithThread;
class Module;

class Process : public WinHandle
{
private:
	pid_t id_;
public:
	Process(pid_t id, handle_t handle)
		: WinHandle(handle, CloseHandle)
		, id_(id)
	{}
	Process()
		: Process(0, nullptr)
	{}

	pid_t id() const
	{
		return id_;
	}

	fs::path path() const
	{
		WCHAR buffer[MAX_PATH + 1] = { 0 };
		if (!GetModuleFileNameExW(handle(), (HMODULE)0, buffer, MAX_PATH))
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("GetModuleFileNameEx") << e_text("could not get path to process") << e_process(*this) << e_last_error(errcode));
		}
		return buffer;
	}

	void waitForInputIdle(DWORD millis) const
	{
		if (WaitForInputIdle(handle(), millis) != 0)
			BOOST_THROW_EXCEPTION(ex_wait_for_input_idle());
	}

	bool isRunning()
	{
		return wait(0) == WAIT_TIMEOUT;
	}

	void kill(UINT exitCode = 1)
	{
		if (!TerminateProcess(handle(), exitCode))
		{
			DWORD errcode = GetLastError();
			if (isRunning())
				BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("TerminateProcess") << e_text("error killing process") << e_process(*this) << e_last_error(errcode));
			//otherwise it was already dead
		}
	}


	void suspend(bool _suspend = true) const;
	void resume(bool _resume = true) const
	{
		suspend(!_resume);
	}

	void suspendAllThreads(bool _suspend = true) const;
	void resumeAllThreads(bool _resume = true) const
	{
		suspendAllThreads(!_resume);
	}

	vector<Thread> threads(bool inheritHandle = false, DWORD desiredAccess = THREAD_SET_INFORMATION) const;


public: // memory
	template <typename T>
	MemoryAreaT<T> alloc(bool freeOnDestruction = true,
		DWORD allocationType = MEM_COMMIT | MEM_RESERVE,
		DWORD protect = PAGE_EXECUTE_READWRITE,
		void* addressHint = nullptr)
	{
		return MemoryAreaT<T>::alloc(*this, freeOnDestruction, allocationType, protect, addressHint);
	}
	MemoryArea alloc(SIZE_T size,
		bool freeOnDestruction = true,
		DWORD allocationType = MEM_COMMIT | MEM_RESERVE,
		DWORD protect = PAGE_EXECUTE_READWRITE,
		void* addressHint = nullptr);

	template <typename T>
	MemoryAreaT<T> memory(void* address)
	{
		return MemoryAreaT<T>(*this, address, false);
	}
	MemoryArea memory(void* address, SIZE_T size);


public:
	Module inject(const Library& lib);
	Module mapRemoteModule(const Library& lib);

	void callTlsInitializers(HMODULE hModule, DWORD fdwReason, IMAGE_TLS_DIRECTORY& imgTlsDir);
	void fixIAT(const boost::interprocess::mapped_region& imageBase, IMAGE_NT_HEADERS& nt_header, IMAGE_IMPORT_DESCRIPTOR* imgImpDesc);

	bool is64bit() const;
	MEMORY_BASIC_INFORMATION memBasicInfo(const void* addr)
	{
		MEMORY_BASIC_INFORMATION mem_basic_info = { 0 };
		SIZE_T size = VirtualQueryEx(handle(), addr, &mem_basic_info, sizeof(MEMORY_BASIC_INFORMATION));
		if (!size)
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("VirtualQueryEx") << e_process(*this) << e_last_error(errcode));
		}
		return mem_basic_info;
	}

	// returns the injected module or an empty Module
	Module isInjected(const Library& lib);
	// returns the injected module or an empty Module
	Module isInjected(HMODULE hmodule);
	/// returns the injected module or throws
	Module getInjected(const Library& lib);
	// returns the injected module or throws
	Module getInjected(HMODULE hmodule);

	void listModules();

	Module map(const File& file);

	DWORD runInHiddenThread(PTHREAD_START_ROUTINE startAddress, LPVOID parameter);
	Thread createRemoteThread(PTHREAD_START_ROUTINE startAddr, LPVOID parameter, DWORD creationFlags = 0,
		LPSECURITY_ATTRIBUTES attr = nullptr, SIZE_T stackSize = 0)
	{
		DWORD tid;
		handle_t thandle = CreateRemoteThread(handle(), attr, stackSize, startAddr, parameter, creationFlags, &tid);
		if (!thandle)
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("CreateRemoteThread") << e_text("could not create thread in remote process") << e_process(*this) << e_last_error(errcode));
		}
		else
			return Thread(tid, thandle);
	}

	void remoteDllMainCall(void* moduleEntry, HMODULE hModule, DWORD ul_reason_for_call, void* lpReserved);
	void mapSections(void* moduleBase, byte* dllBin, IMAGE_NT_HEADERS& nt_header);

	WinHandle openToken(DWORD desiredAccess)
	{
		HANDLE hToken = nullptr;
		if (!OpenProcessToken(handle(), desiredAccess, &hToken))
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("OpenProcessToken") << e_last_error(errcode));
		}
		return WinHandle(hToken, CloseHandle);
	}

	void enablePrivilege(wstring privilegeName, bool enable = true)
	{
		LUID luid = {0};
		if (!LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid))
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("LookupPrivilegeValue") << e_text("could not look up privilege value for '" + to_string(privilegeName) + "'") << e_last_error(errcode));
		}
		if (luid.LowPart == 0 && luid.HighPart == 0)
			BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("LookupPrivilegeValue") << e_text("could not get LUID for '" + to_string(privilegeName)+"'"));

		// Set the privileges we need
		TOKEN_PRIVILEGES token_privileges = {1};
		token_privileges.Privileges[0].Luid = luid;
		token_privileges.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

		// Apply the adjusted privileges
		WinHandle token = openToken(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ);
		if (!AdjustTokenPrivileges(token.handle(), FALSE, &token_privileges, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)0, (PDWORD)0))
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("AdjustTokenPrivileges") << e_text("could not adjust token privileges") << e_last_error(errcode));
		}
	}

public:
	static Process open(const pid_t& pid, bool inheritHandle = false, DWORD desiredAccess =
			PROCESS_QUERY_INFORMATION	| // Required by Alpha
			PROCESS_CREATE_THREAD		| // For CreateRemoteThread
			PROCESS_VM_OPERATION		| // For VirtualAllocEx/VirtualFreeEx
			PROCESS_VM_WRITE			| // For WriteProcessMemory
			PROCESS_SUSPEND_RESUME		|
			SYNCHRONIZE					|
			PROCESS_VM_READ
		);

	// Creates a new process and its primary thread.
	// The new process runs in the security context of the calling process.
	static ProcessWithThread launch(const fs::path& app, const wstring& args = L"",
		optional<Environment> env = {},
		optional<wstring> cwd = {},
		bool inheritHandles = false, DWORD creationFlags = 0,
		SECURITY_ATTRIBUTES* processAttributes = nullptr, SECURITY_ATTRIBUTES* threadAttributes = nullptr,
		STARTUPINFOW startupInfo = {});

	static Process findByExeName(wstring name);
	static Process findByWindow(wstring className, wstring windowName);

public:
	virtual operator bool() const override
	{
		return id() != 0 || handle() != nullptr;
	}

	static Process current;
};

struct ProcessWithThread
{
	Process process;
	Thread thread;

	ProcessWithThread(const Process& process, const Thread& thread)
		: process(process)
		, thread(thread)
	{}
};
