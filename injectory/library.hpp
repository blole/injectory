#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injectory/process.hpp"
#include "injectory/module.hpp"
#include "injectory/file.hpp"

class Library
{
public:
	const path path;

public:
	Library(const boost::filesystem::path& path_)
		: path(path_)
	{
		if (!boost::filesystem::is_regular_file(path))
			BOOST_THROW_EXCEPTION(ex_file_not_found() << e_library(*this));
	}

	Library(const char* path_)
		: Library(boost::filesystem::path(path_))
	{}

	Library(const wchar_t* path_)
		: Library(boost::filesystem::path(path_))
	{}

public:
	File file() const
	{
		return File::create(path);
	}

	wstring ntFilename() const
	{
		return Process::current.map(file()).mappedFilename();
	}
};
