#include "injectory/common.hpp"

void PrintErrorMsgA(char *format, ...)
{
	va_list ap;
	DWORD dwLastError = 0;
	va_start(ap, format);
	
	//printf("Error: ");
	vprintf(format, ap);
	va_end(ap);

	dwLastError = GetLastError();
	if(dwLastError)
	{
		printf(" [LastError: %d]", GetLastError());
	}
	SetLastError(0);
	printf("\n");
}
