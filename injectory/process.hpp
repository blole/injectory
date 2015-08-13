#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injectory/thread.hpp"
#include "injectory/library.hpp"
#include "injectory/module.hpp"
#include <winnt.h>
#include <boost/optional.hpp>

struct ProcessWithThread;

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
		DWORD ret = WaitForSingleObject(handle(), millis);
		if (ret == WAIT_FAILED)
			BOOST_THROW_EXCEPTION(ex_wait_for_exit());
		else
			return ret;
	}

	void kill(UINT exitCode = 1)
	{
		BOOL ret = TerminateProcess(handle(), exitCode);
		if (!ret)
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("error killing process") << e_pid(id()) << e_last_error());
	}


	void suspend(bool _suspend = true) const;
	void resume(bool _resume = true) const
	{
		suspend(!_resume);
	}

	Module inject(const Library& lib, const bool& verbose = false);
	void mapRemoteModule(const Library& lib, const bool& verbose = false);
	void eject(const Module& module);
	void eject(const Library& lib);

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
	Module findModule(const Library& lib);

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
	void listModules();
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
