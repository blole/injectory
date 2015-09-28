#pragma once
#include "injectory/exception.hpp"
#include <algorithm>


template <typename T>
class Handle
{
private:
	shared_ptr<T> handle_;

public:
	Handle(T* handle = nullptr)
		: handle_(handle, [](const T*){})
	{}

	template <class Deleter>
	Handle(T* handle, Deleter deleter)
		: handle_(handle, deleter)
	{}
	virtual ~Handle()
	{}

public:
	T* handle() const
	{
		return handle_.get();
	}

	virtual operator bool() const
	{
		return handle() != nullptr;
	}
};
