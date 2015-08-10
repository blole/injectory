#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injector_helper.hpp"

class Library
{
public:
	const path path;

public:
	Library(const boost::filesystem::path& path)
		: path(path)
	{}

	Library(const char* path)
		: path(path)
	{}

	Library(const wchar_t* path)
		: path(path)
	{}

public:
	wstring ntFilename() const
	{
		WCHAR ntFilename[MAX_PATH + 1] = { 0 };

		if (!GetFileNameNtW(path.c_str(), ntFilename, MAX_PATH))
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not get the NT namespace path"));

		return wstring(ntFilename);
	}
};
