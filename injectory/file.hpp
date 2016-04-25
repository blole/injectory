#pragma once
#include "injectory/exception.hpp"
#include "injectory/handle.hpp"


class File : public WinHandle
{
private:
	fs::path path_;
private:
	explicit File(fs::path path_, handle_t handle)
		: WinHandle(handle, CloseHandle)
		, path_(path_)
	{}
public:
	File()
		: File(fs::path(), nullptr)
	{}

public:
	static File create(fs::path path_,
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
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("CreateFile") << e_file(path_) << e_last_error(errcode));
		}
		else
			return File(path_, handle);
	}

public:
	const fs::path& path() const
	{
		return path_;
	}
};
