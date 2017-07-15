#pragma once
#include "injectory/process.hpp"
#include "injectory/exception.hpp"
#include <unordered_map>
using std::unordered_map;



class Flag;

namespace Flags
{
	unordered_map<string, Flag*> all;
}



class Flag
{
public:
	const string name;

	Flag(string name)
		: name(name)
	{
		Flags::all[this->name] = this;
	}

	virtual void enable() const = 0;
	virtual void disable() const = 0;
};



class LambdaFlag : public Flag
{
public:
	const function<void()> enableFunction;
	const function<void()> disableFunction;

	LambdaFlag(string name, function<void()> enableFunction, function<void()> disableFunction)
		: Flag(name)
		, enableFunction(enableFunction)
		, disableFunction(disableFunction)
	{}

	LambdaFlag(string name, function<void(bool)> setFunction)
		: LambdaFlag(name, std::bind(setFunction, true), std::bind(setFunction, false))
	{}

	void enable() const override
	{
		enableFunction();
	}

	void disable() const override
	{
		disableFunction();
	}
};



class ErrorModeFlag : public Flag
{
public:
	const UINT mode;

	ErrorModeFlag(string name, UINT mode)
		: Flag(name)
		, mode(mode)
	{}

	void enable() const override
	{
		UINT currentMode = SetErrorMode(mode);
		SetErrorMode(currentMode | mode);
	}

	void disable() const override
	{
		UINT currentMode = SetErrorMode(0);
		SetErrorMode(currentMode & ~mode);
	}
};





namespace Flags
{
	const LambdaFlag SeDebugPrivilege("SeDebugPrivilege", [](bool enable) {Process::current.enablePrivilege(L"SeDebugPrivilege", enable);});

	const ErrorModeFlag SEM_FAILCRITICALERRORS_		("SEM_FAILCRITICALERRORS",		SEM_FAILCRITICALERRORS);
	const ErrorModeFlag SEM_NOALIGNMENTFAULTEXCEPT_	("SEM_NOALIGNMENTFAULTEXCEPT",	SEM_NOALIGNMENTFAULTEXCEPT);
	const ErrorModeFlag SEM_NOGPFAULTERRORBOX_		("SEM_NOGPFAULTERRORBOX",		SEM_NOGPFAULTERRORBOX);
	const ErrorModeFlag SEM_NOOPENFILEERRORBOX_		("SEM_NOOPENFILEERRORBOX",		SEM_NOOPENFILEERRORBOX);
}
