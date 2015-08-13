#pragma once
#include "injectory/common.hpp"
#include "injectory/process.hpp"

class MemoryArea
{
private:
	Process process; //to keep from closing the process handle
	shared_ptr<void> handle_;

public:
	explicit MemoryArea(Process process, handle_t handle)
		: process(process)
		, handle_(handle, bind(VirtualFreeEx, process.handle(), std::placeholders::_1, 0, MEM_RELEASE))
	{}

public:
	handle_t handle() const
	{
		return handle_.get();
	}

	void write(LPCVOID from, SIZE_T size)
	{
		SIZE_T writtenSize = 0;
		if (!WriteProcessMemory(process.handle(), handle(), from, size, &writtenSize) || writtenSize != size)
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not write to memory in remote process"));
	}

	void flushInstructionCache(SIZE_T size)
	{
		if (!FlushInstructionCache(process.handle(), handle(), size))
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not flush instruction cache"));
	}
};