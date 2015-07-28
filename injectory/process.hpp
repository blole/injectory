#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injectory/thread.hpp"
#include <winnt.h>


class ProcessWithThread;

class Process
{
private:
	shared_ptr<void> shared_handle;

public:
	const pid_t id;

	explicit Process(pid_t id = 0, handle_t handle = nullptr)
		: id(id)
		, shared_handle(handle, CloseHandle)
	{}

	handle_t handle() const
	{
		return shared_handle.get();
	}

	void waitForInputIdle(DWORD millis = 5000) const
	{
		if (WaitForInputIdle(handle(), millis) != 0)
			BOOST_THROW_EXCEPTION(ex_wait_for_input_idle());
	}

	void suspend(bool _suspend = true) const;
	void resume(bool _resume = true) const
	{
		suspend(!_resume);
	}

	void inject(const path& lib);

	bool is64bit() const;

public:
	static Process open(const pid_t& pid, bool inheritHandle = false, DWORD desiredAccess =
			PROCESS_QUERY_INFORMATION	| // Required by Alpha
			PROCESS_CREATE_THREAD		| // For CreateRemoteThread
			PROCESS_VM_OPERATION		| // For VirtualAllocEx/VirtualFreeEx
			PROCESS_VM_WRITE			| // For WriteProcessMemory
			PROCESS_SUSPEND_RESUME		|
			PROCESS_VM_READ
		);

	/// Creates a new process and its primary thread.
	/// The new process runs in the security context of the calling process.
	static ProcessWithThread launch(const path& application, const wstring& args = L"");
};

class ProcessWithThread : public Process
{
public:
	Thread thread;
public:
	using Process::Process;
	ProcessWithThread(pid_t id, handle_t handle, Thread thread)
		: Process(id, handle)
		, thread(thread)
	{}
};
