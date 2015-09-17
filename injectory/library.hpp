#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injector_helper.hpp"

class Library
{
public:
	const path path;

public:
	Library(const boost::filesystem::path& path_)
		: path(path_)
	{
		if (!boost::filesystem::is_regular_file(path))
			BOOST_THROW_EXCEPTION(ex_file_not_found() << e_library(path));
	}

	Library(const char* path_)
		: Library(boost::filesystem::path(path_))
	{}

	Library(const wchar_t* path_)
		: Library(boost::filesystem::path(path_))
	{}

public:
	wstring ntFilename() const
	{
		WCHAR ntFilename[MAX_PATH + 1] = { 0 };

		if (!GetFileNameNtW(path.c_str(), ntFilename, MAX_PATH))
			BOOST_THROW_EXCEPTION(ex_injection() << e_library(path) << e_text("could not get the NT filename"));
		else
			return wstring(ntFilename);
	}
};
