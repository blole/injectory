#pragma once
#include "injectory/exception.hpp"

class File
{
private:
	path path_;
	shared_ptr<void> handle_;
private:
	explicit File(path path_, handle_t handle)
		: path_(path_)
		, handle_(handle, CloseHandle)
	{}
public:
	File()
		: File(path(), nullptr)
	{}

public:
	static File create(path path_,
		DWORD desiredAccess = GENERIC_READ,
		DWORD shareMode = FILE_SHARE_READ,
		DWORD creationDisposition = OPEN_EXISTING,
		DWORD flagsAndAttributes = 0,
		SECURITY_ATTRIBUTES* securityAttributes = nullptr,
		File templateFile = File())
	{
		HANDLE handle = CreateFileW(path_.c_str(), desiredAccess, shareMode, securityAttributes,
			creationDisposition, flagsAndAttributes, templateFile.handle());

		if (handle == INVALID_HANDLE_VALUE)
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("CreateFileW("+path_.string()+") failed"));
		else
			return File(path_, handle);
	}

public:
	const path& path() const
	{
		return path_;
	}
	handle_t handle() const
	{
		return handle_.get();
	}

	operator bool() const
	{
		return handle() != nullptr;
	}
};
