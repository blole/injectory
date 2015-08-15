#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"


class Process;

class Thread
{
private:
	shared_ptr<void> handle_;
	tid_t id_;

public:
	Thread(tid_t id = 0, handle_t handle = nullptr)
		: id_(id)
		, handle_(handle, CloseHandle)
	{}

	handle_t handle() const
	{
		return handle_.get();
	}
	
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

	DWORD wait(DWORD millis = INFINITE)
	{
		return WaitForSingleObject_Throwing(handle(), millis);
	}
	// returns the threads exit code
	DWORD waitForTermination();

public:
	static Thread open(const tid_t& tid, bool inheritHandle = false, DWORD desiredAccess = THREAD_SET_INFORMATION);
};
