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
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_job() << e_api_function("AssingProcessToJobObject") << e_text("could not assign process to job") << e_last_error(errcode));
		}
	}

	template <typename Info>
	void setInfo(_JOBOBJECTINFOCLASS infoClass, Info info)
	{
		if (!SetInformationJobObject(handle(), infoClass, &info, sizeof(Info)))
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_job() << e_api_function("SetInformationJobObject") << e_text("could not set job information") << e_last_error(errcode));
		}
	}
public:
	static Job create()
	{
		HANDLE handle = CreateJobObjectW(nullptr, nullptr);
		if (!handle)
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_job() << e_api_function("CreateJobObject") << e_text("could not create job") << e_last_error(errcode));
		}
		return Job(handle);
	}
};
