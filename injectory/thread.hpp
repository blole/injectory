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
		DWORD res;
		if (_suspend)
			res = SuspendThread(handle());
		else
			res = ResumeThread(handle());
		if (res == (DWORD)-1)
			BOOST_THROW_EXCEPTION(ex_suspend_resume_thread());
	}
	void resume(bool _resume = true) const
	{
		suspend(!_resume);
	}

	void hideFromDebugger() const;

	void setPriority(int priority);

	// returns the threads exit code
	DWORD waitForTermination();

public:
	static Thread open(const tid_t& tid, bool inheritHandle = false, DWORD desiredAccess = THREAD_SET_INFORMATION);
};
