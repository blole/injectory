#pragma once
#include "injectory/common.hpp"
#include "injectory/process.hpp"

class MemoryArea
{
private:
	Process process; //keeps from closing the process handle, among other things
	shared_ptr<void> address_;
	SIZE_T size;

private:
	explicit MemoryArea(Process process, void* address, SIZE_T size, bool freeOnDestruction = true)
		: process(process)
		, size(size)
	{
		if (freeOnDestruction)
			address_ = shared_ptr<void>(address, bind(VirtualFreeEx, process.handle(), std::placeholders::_1, 0, MEM_RELEASE));
		else
			address_ = shared_ptr<void>(address);
	}

public:
	static MemoryArea alloc(const Process& proc, SIZE_T size,
		bool freeOnDestruction = true,
		DWORD allocationType = MEM_COMMIT | MEM_RESERVE,
		DWORD protect = PAGE_EXECUTE_READWRITE,
		LPVOID address = nullptr)
	{
		LPVOID area = VirtualAllocEx(proc.handle(), address, size, allocationType, protect);

		if (!area)
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not allocate memory in remote process"));
		else
			return MemoryArea(proc, area, size, freeOnDestruction);
	}


public:
	void* address() const
	{
		return address_.get();
	}

	void write(LPCVOID from, SIZE_T size)
	{
		SIZE_T writtenSize = 0;
		if (!WriteProcessMemory(process.handle(), address(), from, size, &writtenSize) || writtenSize != size)
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not write to memory in remote process"));
	}

	void flushInstructionCache(SIZE_T size)
	{
		if (!FlushInstructionCache(process.handle(), address(), size))
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not flush instruction cache"));
	}
};