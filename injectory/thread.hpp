#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injectory/winhandle.hpp"


class Process;

class Thread : public WinHandle
{
private:
	tid_t id_;

public:
	Thread(tid_t id = 0, handle_t handle = nullptr)
		: WinHandle(handle, CloseHandle)
		, id_(id)
	{}

	tid_t id() const
	{
		return id_;
	}

	void suspend(bool _suspend = true) const
	{
		if (!_suspend)
			resume();
		else if (SuspendThread(handle()) == -1)
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_suspend_resume_thread() << e_api_function("SuspendThread") << e_last_error(errcode));
		}
	}
	void resume(bool _resume = true) const
	{
		if (!_resume)
			suspend();
		else if (ResumeThread(handle()) == -1)
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_suspend_resume_thread() << e_api_function("ResumeThread") << e_last_error(errcode));
		}
	}

	void hideFromDebugger() const;

	void setPriority(int priority);

	// returns the threads exit code
	DWORD waitForTermination();

public:
	static Thread open(const tid_t& tid, bool inheritHandle = false, DWORD desiredAccess = THREAD_SET_INFORMATION);
};
