#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injectory/process.hpp"
#include "injectory/module.hpp"
#include "injectory/file.hpp"

class Library
{
private:
	const fs::path path_;

public:
	Library(const fs::path& path_)
		: path_(path_)
	{
		if (!fs::is_regular_file(path_))
			BOOST_THROW_EXCEPTION(ex_file_not_found() << e_library(path_));
	}

public:
	const fs::path& path() const
	{
		return path_;
	}

	File file() const
	{
		return File::create(path_);
	}

	wstring ntFilename() const
	{
		return Process::current.map(file()).mappedFilename();
	}
};
