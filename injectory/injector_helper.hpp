#pragma once
#include "injectory/common.hpp"

BOOL
EnablePrivilegeW(
	LPCWSTR	lpPrivilegeName,
	BOOL bEnable
	);

BOOL
GetFileNameNtW(
	LPCWSTR lpFileName,
	LPWSTR lpFileNameNt,
	DWORD nSize
	);
