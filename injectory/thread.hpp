#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"


class Process;

class Thread
{
private:
	shared_ptr<void> shared_handle;
public:
	const tid_t id;

public:
	Thread(tid_t id = 0, handle_t handle = nullptr)
		: id(id)
		, shared_handle(handle, CloseHandle)
	{}

	handle_t handle() const
	{
		return shared_handle.get();
	}

	void resume() const
	{
		if (ResumeThread(handle()) == (DWORD)-1)
			BOOST_THROW_EXCEPTION(ex_resume_thread());
	}
};
