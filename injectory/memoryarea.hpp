#pragma once
#include "injectory/common.hpp"
#include "injectory/process.hpp"
#include "injectory/api.hpp"

class MemoryAreaBase
{
protected:
	Process process; //keeps from closing the process handle, among other things
	shared_ptr<void> address_;

	MemoryAreaBase(const Process& process, void* address, bool freeOnDestruction = true)
		: process(process)
	{
		if (freeOnDestruction)
			address_ = shared_ptr<void>(address, bind(VirtualFreeEx, process.handle(), std::placeholders::_1, 0, MEM_RELEASE));
		else
			address_ = shared_ptr<void>(address, [](void*){});
	}
	virtual ~MemoryAreaBase()
	{}

	virtual SIZE_T size() const = 0;

public:
	void* address() const
	{
		return address_.get();
	}

	void flushInstructionCache()
	{
		if (!FlushInstructionCache(process.handle(), address(), size()))
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("FlushInstructionCache") << e_text("could not flush instruction cache") << e_last_error(errcode) << e_pid(process.id()));
		}
	}
};

class MemoryArea : public MemoryAreaBase
{
	friend MemoryArea Process::alloc(SIZE_T, bool, DWORD, DWORD, void*);
	friend MemoryArea Process::memory(void*, SIZE_T);
protected:
	const SIZE_T size_;

	MemoryArea(const Process& process, void* address, SIZE_T size, bool freeOnDestruction = true)
		: MemoryAreaBase(process, address, freeOnDestruction)
		, size_(size)
	{}

	static MemoryArea alloc(const Process& proc, SIZE_T size, bool freeOnDestruction,
		DWORD allocationType, DWORD protect, void* addressHint)
	{
		void* address = VirtualAllocEx_Throwing(proc, addressHint, size, allocationType, protect);
		return MemoryArea(proc, address, size, freeOnDestruction);
	}

public:
	virtual SIZE_T size() const override
	{
		return size_;
	}

	void write(const void* src)
	{
		write(src, size());
	}

	void write(const void* src, SIZE_T size)
	{
		WriteProcessMemory_Throwing(process, address(), src, size);
		flushInstructionCache();
	}

	vector<byte> read() const
	{
		vector<byte> buf(size());
		ReadProcessMemory_Throwing(process, address(), &buf[0], buf.size());
		return buf;
	}
};

template<typename T>
class MemoryAreaT : public MemoryAreaBase
{
	friend MemoryAreaT<T> Process::alloc(bool, DWORD, DWORD, void*);
	friend MemoryAreaT<T> Process::memory(void*);
protected:
	using MemoryAreaBase::MemoryAreaBase;

	static MemoryAreaT<T> alloc(const Process& proc, bool freeOnDestruction,
		DWORD allocationType, DWORD protect, void* addressHint)
	{
		void* area = VirtualAllocEx_Throwing(proc, addressHint, sizeof(T), allocationType, protect);
		return MemoryAreaT<T>(proc, area, freeOnDestruction);
	}

	virtual SIZE_T size() const override
	{
		return sizeof(T);
	}

public:
	void write(const T* src)
	{
		WriteProcessMemory_Throwing(process, address(), (void*)src, sizeof(T));
		flushInstructionCache();
	}

	T read() const
	{
		T t;
		ReadProcessMemory_Throwing(process, address(), &t, sizeof(T));
		return t;
	}
};


//MemoryArea<vector<byte>> subarea(SIZE_T size0)
//{
//	if (size0 > size())
//		BOOST_THROW_EXCEPTION(ex_injection() << e_text("not a subarea"));
//
//	return MemoryArea<vector<byte>>(process, address_, size0);
//}
//
//template<typename T>
//MemoryArea<T> as()
//{
//	if (sizeof(T) > size())
//		BOOST_THROW_EXCEPTION(ex_injection() << e_text("area too small to be interpreted as " typeid(T)::name()));
//
//	return MemoryArea<T>(process, address_, sizeof(T));
//}
