#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injectory/winhandle.hpp"
#include "injectory/process.hpp"


class Job : public WinHandle
{
public:
	Job(handle_t handle = nullptr)
		: WinHandle(handle, CloseHandle)
	{}

	void assignProcess(const Process& proc)
	{
		if (!AssignProcessToJobObject(handle(), proc.handle()))
		{
			e_last_error last_error;
			BOOST_THROW_EXCEPTION(ex_job() << e_text("could not assign process to job") << last_error);
		}
	}

	template <typename Info>
	void setInfo(_JOBOBJECTINFOCLASS infoClass, Info info)
	{
		if (!SetInformationJobObject(handle(), infoClass, &info, sizeof(Info)))
		{
			e_last_error last_error;
			BOOST_THROW_EXCEPTION(ex_job() << e_text("could not set job information") << last_error);
		}
	}
public:
	static Job create()
	{
		HANDLE handle = CreateJobObjectW(nullptr, nullptr);
		if (!handle)
		{
			e_last_error last_error;
			BOOST_THROW_EXCEPTION(ex_job() << e_text("could not create job") << last_error);
		}
		return Job(handle);
	}
};
