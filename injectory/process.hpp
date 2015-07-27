#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include <winnt.h>


class Process
{
private:
	PROCESS_INFORMATION pi;

public:
	pid_t& pid = pi.dwProcessId;
	tid_t& tid = pi.dwThreadId;
	handle_t&	hProcess = pi.hProcess;
	handle_t&	hThread = pi.hThread;

	Process()
		: pi({ 0 })
	{}

	Process(Process&& original)
		: pi(original.pi)
	{
		original.pi = { 0 };
	}

	virtual ~Process()
	{
		CloseHandle(hThread);
		CloseHandle(hProcess);
	}

	void resumeThread()
	{
		if (ResumeThread(hThread) == (DWORD)-1)
			BOOST_THROW_EXCEPTION(ex_resume_process());
	}

	void waitForInputIdle(DWORD millis = 5000)
	{
		if (WaitForInputIdle(hProcess, millis) != 0)
			BOOST_THROW_EXCEPTION(ex_wait_for_input_idle());
	}

	void inject(const path& lib);

public:
	static Process open(const pid_t& pid, bool inheritHandle = false, DWORD desiredAccess =
			PROCESS_QUERY_INFORMATION	| // Required by Alpha
			PROCESS_CREATE_THREAD		| // For CreateRemoteThread
			PROCESS_VM_OPERATION		| // For VirtualAllocEx/VirtualFreeEx
			PROCESS_VM_WRITE			| // For WriteProcessMemory
			PROCESS_VM_READ
		);

	/// Creates a new process and its primary thread.
	/// The new process runs in the security context of the calling process.
	static Process launch(const path& application, const wstring& args = L"");
};
