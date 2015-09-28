#pragma once
#include "injectory/exception.hpp"
#include "injectory/handle.hpp"


class WinHandle : public Handle<void>
{
public:
	WinHandle(handle_t handle = nullptr)
		: Handle<void>(handle)
	{}

	template <class Deleter>
	WinHandle(handle_t handle, Deleter deleter)
		: Handle<void>(handle, deleter)
	{}

public:
	DWORD wait(DWORD millis = INFINITE) const
	{
		DWORD ret = WaitForSingleObject(handle(), millis);
		if (ret == WAIT_FAILED)
			BOOST_THROW_EXCEPTION(ex_wait_for_single_object());
		else
			return ret;
	}

	static DWORD wait(const vector<handle_t>& handles, bool waitAll, DWORD millis = INFINITE)
	{
		//vector<HANDLE> winHandles;
		//std::transform(handles.begin(), handles.end(), std::back_inserter(winHandles), [](const WinHandle& h) {return h.handle();});

		//DWORD ret = WaitForMultipleObjects(handles.size(), &winHandles[0], false, INFINITY);
		DWORD ret = WaitForMultipleObjects(handles.size(), &handles[0], false, INFINITY);
		if (ret == WAIT_FAILED)
			BOOST_THROW_EXCEPTION(ex_wait_for_multiple_objects());
		else
			return ret;
	}

public:
	static const WinHandle& std_in();
	static const WinHandle& std_out();
	static const WinHandle& std_err();
};
