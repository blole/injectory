#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injectory/thread.hpp"
#include <winnt.h>
#include <boost/optional.hpp>

class Library;
class File;
class MemoryArea;
struct ProcessWithThread;
class Module;

class Process
{
private:
	shared_ptr<void> handle_;
	pid_t id_;
	bool resumeOnDestruction;
public:
	explicit Process(pid_t id = 0, handle_t handle = nullptr)
		: id_(id)
		, handle_(handle, CloseHandle)
		, resumeOnDestruction(false)
	{}

	virtual ~Process()
	{
		try
		{
			if (resumeOnDestruction)
				resume();
		}
		catch (...) {}
	}

	void tryResumeOnDestruction(bool resume = true)
	{
		resumeOnDestruction = resume;
	}

	handle_t handle() const
	{
		return handle_.get();
	}

	pid_t id() const
	{
		return id_;
	}

	void waitForInputIdle(DWORD millis = 5000) const
	{
		if (WaitForInputIdle(handle(), millis) != 0)
			BOOST_THROW_EXCEPTION(ex_wait_for_input_idle());
	}

	DWORD wait(DWORD millis = INFINITE)
	{
		return WaitForSingleObject_Throwing(handle(), millis);
	}

	bool isRunning()
	{
		return wait(0) == WAIT_TIMEOUT;
	}

	void kill(UINT exitCode = 1)
	{
		if (!TerminateProcess(handle(), exitCode))
		{
			e_last_error last_error;
			if (isRunning())
				BOOST_THROW_EXCEPTION(ex_injection() << e_text("error killing process") << e_pid(id()) << last_error);
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

	MemoryArea alloc(SIZE_T size,
		bool freeOnDestruction = true,
		DWORD allocationType = MEM_COMMIT | MEM_RESERVE,
		DWORD protect = PAGE_EXECUTE_READWRITE,
		LPVOID address = nullptr);

	Module inject(const Library& lib, const bool& verbose = false);
	void mapRemoteModule(const Library& lib, const bool& verbose = false);

	void callTlsInitializers(PBYTE imageBase, PIMAGE_NT_HEADERS pNtHeader, HMODULE hModule, DWORD fdwReason, PIMAGE_TLS_DIRECTORY pImgTlsDir);
	void fixIAT(PBYTE imageBase, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_IMPORT_DESCRIPTOR pImgImpDesc);

	bool is64bit() const;
	MEMORY_BASIC_INFORMATION memBasicInfo(LPCVOID addr)
	{
		MEMORY_BASIC_INFORMATION mem_basic_info = { 0 };
		if (!VirtualQueryEx(handle(), addr, &mem_basic_info, sizeof(MEMORY_BASIC_INFORMATION)))
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("VirtualQueryEx failed") << e_pid(id()));
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

	DWORD runInHiddenThread(LPTHREAD_START_ROUTINE startAddress, LPVOID parameter);
	Thread createRemoteThread(LPTHREAD_START_ROUTINE startAddr, LPVOID parameter, DWORD creationFlags = 0,
		LPSECURITY_ATTRIBUTES attr = nullptr, SIZE_T stackSize = 0)
	{
		DWORD tid;
		handle_t thandle = CreateRemoteThread(handle(), attr, stackSize, startAddr, parameter, creationFlags, &tid);
		if (!thandle)
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not create thread in remote process") << e_pid(id()));
		else
			return Thread(tid, thandle);
	}

	void remoteDllMainCall(LPVOID lpModuleEntry, HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);
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
	static ProcessWithThread launch(const path& app, const wstring& args = L"",
		boost::optional<const vector<string>&> env = boost::none,
		boost::optional<const wstring&> cwd = boost::none,
		bool inheritHandles = false, DWORD creationFlags = 0,
		SECURITY_ATTRIBUTES* processAttributes = nullptr, SECURITY_ATTRIBUTES* threadAttributes = nullptr,
		STARTUPINFOW* startupInfo = { 0 });

public:
	operator bool() const
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
