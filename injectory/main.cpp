////////////////////////////////////////////////////////////////////////////////////////////
// loader: command-line interface dll injector
// Copyright (C) 2009-2011 Wadim E. <wdmegrv@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
////////////////////////////////////////////////////////////////////////////////////////////
#include "injectory/main.hpp"

void PrintUsage(void)
{
	const char *usagetext =
		"Usage: loader\t[[--pid %%d/%%x] | [--procname %%s] | [--wndtitle %%s] |\n"
		"\t\t[--wndclass %%s] | [--launch %%s]] [--lib %%s/%%p] [--args %%s]\n"
		"\t\t[--mm] [--dbgpriv] [--wii] [--listmodules %%d/%%x] [--eject]\n"
		"\t\t[--help]\n\n"
		"Options:\n"
		" --pid \t\t[%%d/%%x]\tInjection via process id.\n"
		" --procname \t[%%s]\tInjection via process name.\n"
		" --wndtitle \t[%%s]\tInjection via window title.\n"
		" --wndclass \t[%%s]\tInjection via window class.\n"
		" --lib \t\t[%%s/%%p]\tFull qualified path to library/\n"
		"\t\t\tAddress of library (ejection).\n"
		" --launch \t[%%s]\tFull qualified path to target process.\n"
		" --args \t[%%s]\tArguments for target process.\n"
		" --mm \t\t[-]\tMap the PE file into the remote address space of \n"
		"\t\t\ta process (without calling LoadLibrary).\n"
		" --eject \t[-]\tSet to ejection mode.\n"
		" --dbgpriv \t[-]\tSet SeDebugPrivilege.\n"
		" --wii \t\t[-]\tWait until process is initialized (WaitForInputIdle).\n"
		" --listmodules\t[%%d/%%x]\tDump modules associated with the specified process id.\n"
		" --help \t[-]\tProduce help message.\n\n";
	printf(usagetext);
}

int compare_option(enum option_enum opt, const char *arg)
{
	return strncmp(arg, option_list[opt], strlen(option_list[opt]) + 1) == 0;
}

int commandline_parser(int argc, char *argv[])
{
	int argv_index				= 1;
	int ldr_eject				= 0;
	int ldr_wii					= 0;
	int ldr_mm					= 0;
	unsigned long process_id	= 0;
	char *process_name			= 0;
	char *window_title			= 0;
	char *window_class			= 0;
	char *library_path			= 0;
	char *process_path			= 0;
	char *process_arguments		= 0;
	void *library_address		= 0;
	
	__try
	{
		for(argv_index = 1; argv_index < argc; argv_index++)
		{
			// option:	"--help"
			if(CMP_OPT(o_help))
			{
				PrintUsage();
			}

			// option:	"--eject"
			if(CMP_OPT(o_eject))
			{
				ldr_eject = 1;
			}

			// option:	"--dbgpriv"
			if(CMP_OPT(o_dbgpriv))
			{
				if(!EnablePrivilegeW(L"SeDebugPrivilege", TRUE))
				{
					PRINT_ERROR_MSGA("Could not set SeDebugPrivilege.");
				}
			}

			// option:	"--wii"
			if(CMP_OPT(o_wii))
			{
				ldr_wii = 1;
			}

			// option:	"--mm"
			if(CMP_OPT(o_mm))
			{
				ldr_mm = 1;
			}

			// option:	"--pid"	
			if(CMP_OPT(o_pid))
			{
				// not enough arguments
				if(argv[argv_index + 1] == 0)
				{
					PRINT_ERROR_MSGA("Not enough arguments (%s).", argv[argv_index]);
					goto clean_up;
				}

				process_id = parse_int(argv[argv_index + 1]);

				// invalid argument
				if(process_id == 0)
				{
					PRINT_ERROR_MSGA("Invalid argument (%s).", argv[argv_index + 1]);
					goto clean_up;
				}

				continue;
			}

			// option:	"--procname"
			if(CMP_OPT(o_procname))
			{
				// not enough arguments
				if(argv[argv_index + 1] == 0)
				{
					PRINT_ERROR_MSGA("Not enough arguments (%s).", argv[argv_index]);
					goto clean_up;
				}

				if((process_name = alloc_stra(argv[argv_index + 1])) == 0)
				{
					goto clean_up;
				}

				continue;
			}

			// option:	"--wndtitle"
			if(CMP_OPT(o_wndtitle))
			{
				// not enough arguments
				if(argv[argv_index + 1] == 0)
				{
					PRINT_ERROR_MSGA("Not enough arguments (%s).", argv[argv_index]);
					goto clean_up;
				}
				
				if((window_title = alloc_stra(argv[argv_index + 1])) == 0)
				{
					goto clean_up;
				}
				
				continue;
			}

			// option:	"--wndclass"
			if(CMP_OPT(o_wndclass))
			{
				// not enough arguments
				if(argv[argv_index + 1] == 0)
				{
					PRINT_ERROR_MSGA("Not enough arguments (%s).", argv[argv_index]);
					goto clean_up;
				}
				
				if((window_class = alloc_stra(argv[argv_index + 1])) == 0)
				{
					goto clean_up;
				}
				
				continue;
			}

			// option:	"--lib"
			if(CMP_OPT(o_lib))
			{
				// not enough arguments
				if(argv[argv_index + 1] == 0)
				{
					PRINT_ERROR_MSGA("Not enough arguments (%s).", argv[argv_index]);
					goto clean_up;
				}
				
				sscanf_s(argv[argv_index + 1], "0x%p", &library_address);

				if((library_path = alloc_stra(argv[argv_index + 1])) == 0)
				{
					goto clean_up;
				}
				
				continue;
			}

			// option:	"--launch"
			if(CMP_OPT(o_launch))
			{
				// not enough arguments
				if(argv[argv_index + 1] == 0)
				{
					PRINT_ERROR_MSGA("Not enough arguments (%s).", argv[argv_index]);
					goto clean_up;
				}
				
				if((process_path = alloc_stra(argv[argv_index + 1])) == 0)
				{
					goto clean_up;
				}
				
				continue;
			}

			// option:	"--args"
			if(CMP_OPT(o_args))
			{
				// not enough arguments
				if(argv[argv_index + 1] == 0)
				{
					PRINT_ERROR_MSGA("Not enough arguments (%s).", argv[argv_index]);
					goto clean_up;
				}
				
				if((process_arguments = alloc_stra(argv[argv_index + 1])) == 0)
				{
					goto clean_up;
				}
				
				continue;
			}

			// Dump modules associated with the specified process id
			// option:	"--listmodules"	
			if(CMP_OPT(o_listmodules))
			{
				// not enough arguments
				if(argv[argv_index + 1] == 0)
				{
					PRINT_ERROR_MSGA("Not enough arguments (%s).",
						argv[argv_index]);
					goto clean_up;
				}

				process_id = parse_int(argv[argv_index + 1]);

				// invalid argument
				if(process_id == 0)
				{
					PRINT_ERROR_MSGA("Invalid argument (%s).",
						argv[argv_index + 1]);
					goto clean_up;
				}

				if(!CHECK_TARGET_PROC(process_id))
				{
					PRINT_TARGET_PROC_ERROR(process_id);
					goto clean_up;
				}

				ListModules(process_id);
				
				goto clean_up;
			}
		}


		// inject/ eject via process id
		if(process_id && (library_path || library_address))
		{
			if(!CHECK_TARGET_PROC(process_id))
			{
				PRINT_TARGET_PROC_ERROR(process_id);
				goto clean_up;
			}

			if(ldr_eject)
			{
				BOOL eject = FALSE;
				if(library_address)
				{
					eject = EjectLibrary(process_id, library_address);
				}
				else if(library_path)
				{
					eject = EjectLibraryA(process_id, library_path);
				}
				if(!eject)
				{
					PRINT_ERROR_MSGA("Ejection failed.");
				}
			}
			else
			{
				if(ldr_mm)
				{
					if(!MapRemoteModuleA(process_id, library_path))
					{
						PRINT_ERROR_MSGA("Injection failed.");
					}
				}
				else
				{
					if(!InjectLibraryA(process_id, library_path))
					{
						PRINT_ERROR_MSGA("Injection failed.");
					}
				}
			}

			goto clean_up;
		}

		// inject/ eject via process name
		if(process_name && (library_path || library_address))
		{
			InjectEjectToProcessNameA(process_name, library_path,
				library_address, !ldr_eject, ldr_mm);
			goto clean_up;
		}

		// inject/ eject via window title
		if(window_title && (library_path || library_address))
		{
			InjectEjectToWindowTitleA(window_title, library_path,
				library_address, !ldr_eject, ldr_mm);
			goto clean_up;
		}

		// inject/ eject via window class
		if(window_class && (library_path || library_address))
		{
			InjectEjectToWindowClassA(window_class, library_path,
				library_address, !ldr_eject, ldr_mm);
			goto clean_up;
		}

		if(library_path && process_path)
		{
			if(ldr_eject)
			{
				if(!EjectLibraryOnStartupA(library_path, process_path,
					process_arguments == 0 ? "" : process_arguments, ldr_wii))
				{
					PRINT_ERROR_MSGA("Ejection failed.");
				}
			}
			else
			{
				if(!InjectLibraryOnStartupA(library_path, process_path,
					process_arguments == 0 ? "" : process_arguments, ldr_wii))
				{
					PRINT_ERROR_MSGA("Injection failed.");
				}
			}
			goto clean_up;
		}
	}
	__except(1)
	{
		PRINT_ERROR_MSGA("SEH Exception: %X\n", GetExceptionCode());
	}

	//
	// clean up
	//
clean_up:
	if(process_name) free(process_name);
	if(window_title) free(window_title);
	if(window_class) free(window_class);
	if(library_path) free(library_path);
	if(process_path) free(process_path);
	if(process_arguments) free(process_arguments);

	return 1;
}

int main(int argc, char *argv[])
{
	printf("Loader v%s by Wadim E.\n"
		"Project Home: injector.googlecode.com\n"
		"Copyright (C) 2011 Wadim E.\n"
		"Email: wdmegrv@gmail.com\n\n", VERSION);

	if(argc < 2)
	{
		PRINT_ERROR_MSGA("Not enough or invalid arguments.");
		return 0;
	}

	commandline_parser(argc, argv);

	return 0;
}