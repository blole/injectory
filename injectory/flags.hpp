#pragma once
#include "injectory/process.hpp"
#include "injectory/exception.hpp"

class Flag;

namespace Flags
{
	unordered_map<string, Flag*> all;
}



class Flag
{
public:
	const string name;
	const string group;

	Flag(string name, string group)
		: name(name)
		, group(group)
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

	LambdaFlag(string name, string group, function<void()> enableFunction, function<void()> disableFunction)
		: Flag(name, group)
		, enableFunction(enableFunction)
		, disableFunction(disableFunction)
	{}

	LambdaFlag(string name, string group, function<void(bool)> setFunction)
		: LambdaFlag(name, group, std::bind(setFunction, true), std::bind(setFunction, false))
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



class PrivilegeFlag : public Flag
{
public:
	PrivilegeFlag(string name)
		: Flag(name, "privilege")
	{}

	void enable() const override
	{
		Process::current.enablePrivilege(to_wstring(name), true);
	}

	void disable() const override
	{
		Process::current.enablePrivilege(to_wstring(name), false);
	}
};



class ErrorModeFlag : public Flag
{
public:
	const UINT mode;

	ErrorModeFlag(string name, UINT mode)
		: Flag(name, "error mode")
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
	const PrivilegeFlag SeCreateTokenPrivilege			("SeCreateTokenPrivilege");
	const PrivilegeFlag SeAssignPrimaryTokenPrivilege	("SeAssignPrimaryTokenPrivilege");
	const PrivilegeFlag SeLockMemoryPrivilege			("SeLockMemoryPrivilege");
	const PrivilegeFlag SeIncreaseQuotaPrivilege		("SeIncreaseQuotaPrivilege");
	const PrivilegeFlag SeUnsolicitedInputPrivilege		("SeUnsolicitedInputPrivilege");
	const PrivilegeFlag SeMachineAccountPrivilege		("SeMachineAccountPrivilege");
	const PrivilegeFlag SeTcbPrivilege					("SeTcbPrivilege");
	const PrivilegeFlag SeSecurityPrivilege				("SeSecurityPrivilege");
	const PrivilegeFlag SeTakeOwnershipPrivilege		("SeTakeOwnershipPrivilege");
	const PrivilegeFlag SeLoadDriverPrivilege			("SeLoadDriverPrivilege");
	const PrivilegeFlag SeSystemProfilePrivilege		("SeSystemProfilePrivilege");
	const PrivilegeFlag SeSystemtimePrivilege			("SeSystemtimePrivilege");
	const PrivilegeFlag SeProfileSingleProcessPrivilege	("SeProfileSingleProcessPrivilege");
	const PrivilegeFlag SeIncreaseBasePriorityPrivilege	("SeIncreaseBasePriorityPrivilege");
	const PrivilegeFlag SeCreatePagefilePrivilege		("SeCreatePagefilePrivilege");
	const PrivilegeFlag SeCreatePermanentPrivilege		("SeCreatePermanentPrivilege");
	const PrivilegeFlag SeBackupPrivilege				("SeBackupPrivilege");
	const PrivilegeFlag SeRestorePrivilege				("SeRestorePrivilege");
	const PrivilegeFlag SeShutdownPrivilege				("SeShutdownPrivilege");
	const PrivilegeFlag SeDebugPrivilege				("SeDebugPrivilege");
	const PrivilegeFlag SeAuditPrivilege				("SeAuditPrivilege");
	const PrivilegeFlag SeSystemEnvironmentPrivilege	("SeSystemEnvironmentPrivilege");
	const PrivilegeFlag SeChangeNotifyPrivilege			("SeChangeNotifyPrivilege");
	const PrivilegeFlag SeRemoteShutdownPrivilege		("SeRemoteShutdownPrivilege");
	const PrivilegeFlag SeUndockPrivilege				("SeUndockPrivilege");
	const PrivilegeFlag SeSyncAgentPrivilege			("SeSyncAgentPrivilege");
	const PrivilegeFlag SeEnableDelegationPrivilege		("SeEnableDelegationPrivilege");
	const PrivilegeFlag SeManageVolumePrivilege			("SeManageVolumePrivilege");
	const PrivilegeFlag SeImpersonatePrivilege			("SeImpersonatePrivilege");
	const PrivilegeFlag SeCreateGlobalPrivilege			("SeCreateGlobalPrivilege");
	const PrivilegeFlag SeTrustedCredManAccessPrivilege	("SeTrustedCredManAccessPrivilege");
	const PrivilegeFlag SeRelabelPrivilege				("SeRelabelPrivilege");
	const PrivilegeFlag SeIncreaseWorkingSetPrivilege	("SeIncreaseWorkingSetPrivilege");
	const PrivilegeFlag SeTimeZonePrivilege				("SeTimeZonePrivilege");
	const PrivilegeFlag SeCreateSymbolicLinkPrivilege	("SeCreateSymbolicLinkPrivilege");

	const ErrorModeFlag SEM_FAILCRITICALERRORS_		("SEM_FAILCRITICALERRORS",		SEM_FAILCRITICALERRORS);
	const ErrorModeFlag SEM_NOALIGNMENTFAULTEXCEPT_	("SEM_NOALIGNMENTFAULTEXCEPT",	SEM_NOALIGNMENTFAULTEXCEPT);
	const ErrorModeFlag SEM_NOGPFAULTERRORBOX_		("SEM_NOGPFAULTERRORBOX",		SEM_NOGPFAULTERRORBOX);
	const ErrorModeFlag SEM_NOOPENFILEERRORBOX_		("SEM_NOOPENFILEERRORBOX",		SEM_NOOPENFILEERRORBOX);
}
