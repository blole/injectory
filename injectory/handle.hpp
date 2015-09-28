#pragma once
#include "injectory/exception.hpp"
#include <algorithm>


class Handle
{
private:
	shared_ptr<void> handle_;

public:
	Handle(handle_t handle = nullptr)
		: handle_(handle, [](const void*){})
	{}

	template <class Deleter>
	Handle(handle_t handle, Deleter deleter)
		: handle_(handle, deleter)
	{}
	virtual ~Handle()
	{}

public:
	handle_t handle() const
	{
		return handle_.get();
	}

	DWORD wait(DWORD millis = INFINITE)
	{
		DWORD ret = WaitForSingleObject(handle(), millis);
		if (ret == WAIT_FAILED)
			BOOST_THROW_EXCEPTION(ex_wait_for_single_object());
		else
			return ret;
	}

	static DWORD wait(const vector<Handle>& handles, bool waitAll, DWORD millis = INFINITE)
	{
		vector<HANDLE> winHandles;
		std::transform(handles.begin(), handles.end(), std::back_inserter(winHandles), [](const Handle& h) {return h.handle();});
		
		DWORD ret = WaitForMultipleObjects(handles.size(), &winHandles[0], false, INFINITY);
		if (ret == WAIT_FAILED)
			BOOST_THROW_EXCEPTION(ex_wait_for_multiple_objects());
		else
			return ret;
	}

	virtual operator bool() const
	{
		return handle() != nullptr;
	}

public:
	static Handle std_in();
	static Handle std_out();
	static Handle std_err();
};
