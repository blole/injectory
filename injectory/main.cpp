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
#undef UNICODE

#include "injectory/misc.hpp"
#include "injectory/findproc.hpp"
#include "injectory/injector_helper.hpp"
#include "injectory/generic_injector.hpp"
#include "injectory/manualmap.hpp"

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <exception>
#include <iostream>
#include <iterator>
using namespace std;

#define VERSION "5.0-SNAPSHOT"


int main(int argc, char *argv[])
{
	try
	{
		po::options_description desc("Usage: injectory [OPTION]...\n"
			"Inject DLL:s into running processes\n"
			"\n"
			"Options");

		desc.add_options()
			("help",													"display help message and exit")
			("version",													"display version information and exit")
			("pid",			po::value<int>()->value_name("<pid>"),		"injection via process id")
			("procname",	po::value<string>()->value_name("<name>"),	"injection via process name")
			("wndtitle",	po::value<string>()->value_name("<title>"),	"injection via window title")
			("wndclass",	po::value<string>()->value_name("<class>"),	"injection via window class")
			("lib",			po::value<string>()->value_name("<file>"),	"fully qualified path to libraries")
			("launch",		po::value<string>()->value_name("<file>"),	"fully qualified path to target process")
			("args",		po::value<string>()->value_name("<args>")->default_value(""),
																		"arguments for target process")
			("mm",													  	"map the PE file into the remote address space of")
			("dbgpriv",												  	"set SeDebugPrivilege")
			("wii",													  	"wait until process is initialized (WaitForInputIdle)")
			//("Address of library (ejection)")
			//("a process (without calling LoadLibrary)")
			//("eject",		po::value<vector<int>>(), "ejection mode")
			//("listmodules",									"dump modules associated with the specified process id")
		;

		po::variables_map vars;
		po::store(po::parse_command_line(argc, argv, desc), vars);
		po::notify(vars);

		if (vars.count("help"))
		{
			cout << desc << endl;
			return 0;
		}
		
		if (vars.count("version"))
		{
			cout << "injectory " << VERSION << endl
				 << "project home: https://github.com/blole/injector" << endl
				 << "forked from:  https://code.google.com/p/injector" << endl
				 << "Copyright (C) 2011 Wadim E. (wdmegrv@gmail.com)" << endl;
			return 0;
		}

		if (vars.count("dbgpriv"))
		{
			if (!EnablePrivilegeW(L"SeDebugPrivilege", TRUE))
				throw runtime_error("could not set SeDebugPrivilege");
		}

		bool eject = vars.count("eject") > 0;
		bool wii = vars.count("wii") > 0;
		bool mm = vars.count("mm") > 0;

		auto var_string = [vars](string var)
		{
			return vars[var].as<string>().c_str();
		};

		if (!vars.count("lib"))
			throw runtime_error("no library path (--lib) given");

		const char* lib = var_string("lib");

		if (vars.count("pid"))
		{
			int pid = vars["pid"].as<int>();

			THROW_IF_TARGET_BIT_MISMATCH(pid);
			
			if (mm)
			{
				if (!MapRemoteModuleA(pid, lib))
					throw runtime_error("injection failed");
			}
			else
			{
				if (!InjectLibraryA(pid, lib))
					throw runtime_error("injection failed");
			}
		}

		if (vars.count("procname"))
			InjectEjectToProcessNameA(var_string("procname"), lib, nullptr, !eject, mm);
		else if (vars.count("wndtitle"))
			InjectEjectToWindowTitleA(var_string("wndtitle"), lib, nullptr, !eject, mm);
		else if (vars.count("wndclass"))
			InjectEjectToWindowClassA(var_string("wndclass"), lib, nullptr, !eject, mm);
		else if (vars.count("launch"))
		{
			if (!InjectLibraryOnStartupA(lib, var_string("launch"), var_string("args"), wii))
				throw runtime_error("injection failed");
		}
	}
	catch (const exception& e)
	{
		cerr << "error: " << e.what() << endl;
		return 1;
	}
	catch (...)
	{
		cerr << "Exception of unknown type!" << endl;
		return 1;
	}

	return 0;
}
