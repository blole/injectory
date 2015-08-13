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

#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injectory/findproc.hpp"
#include "injectory/injector_helper.hpp"
#include "injectory/process.hpp"

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <exception>
#include <iostream>
#include <iterator>
#include <process.h>
using namespace std;

#define VERSION "5.0-SNAPSHOT"

int main(int argc, char *argv[])
{
	try
	{
		po::options_description desc(
			"Usage: injectory [OPTION]...\n"
			"Inject DLL:s into processes\n"
			"<exe> and <dll> can be relative paths\n"
			"\n"
			"Examples:\n"
			"  injectory -l a.exe -i b.dll --wait-for-exit\n"
			"  injectory -l a.exe -i b.dll --args \"1 2 3\"\n"
			"\n"
			"Options");

		desc.add_options()
			("help",													"display help message and exit")
			("version",													"display version information and exit")
			("verbose,v",												"\n")

			("pid",			po::value<int>()->value_name("<pid>"),		"injection via process id")
			//("procname",	po::value<string>()->value_name("<name>"),	"injection via process name")
			//("wndtitle",	po::value<string>()->value_name("<title>"),	"injection via window title")
			//("wndclass",	po::value<string>()->value_name("<class>"),	"injection via window class")
			("launch,l",	po::value<path>()->value_name("<exe>"),		"launches the target in a new process")
			("args",		po::wvalue<wstring>()->value_name("<string>")->default_value(L"", ""),
																		"arguments for --launch:ed process\n")
			
			("inject,i",	po::value<vector<path>>()->value_name("<dll>"),	"inject libraries")
			("eject,e",		po::value<vector<path>>()->value_name("<dll>"),	"eject libraries\n")

			("mm",													  	"map the PE file into the remote address space of")
			("dbgpriv",												  	"set SeDebugPrivilege")
			("print-pid",												"print the pid of the (started) process")
			("wii",													  	"wait for process input idle before injecting")
			("wait-for-exit",											"wait for the target to exit before exiting")
			("kill-on-exit",											"kill the target when exiting") // (also on forced exit)")
			//("Address of library (ejection)")
			//("a process (without calling LoadLibrary)")
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
				BOOST_THROW_EXCEPTION (ex_set_se_debug_privilege() << e_text("could not set SeDebugPrivilege"));
		}

		bool wii = vars.count("wii") > 0;
		bool mm = vars.count("mm") > 0;
		bool verbose = vars.count("verbose") > 0;

		Process proc;

		if (vars.count("pid"))
		{
			int pid = vars["pid"].as<int>();
			proc = Process::open(pid);
			proc.suspend();
		}
		else if (vars.count("launch"))
		{
			using boost::none;
			path    app  = vars["launch"].as<path>();
			wstring args = vars["args"].as<wstring>();
			
			proc = Process::launch(app, args, none, none, false, CREATE_SUSPENDED).process;
		}
		/*
		else if (vars.count("procname"))
		InjectEjectToProcessNameA(var_string("procname"), lib, nullptr, !eject, mm);
		else if (vars.count("wndtitle"))
		InjectEjectToWindowTitleA(var_string("wndtitle"), lib, nullptr, !eject, mm);
		else if (vars.count("wndclass"))
		InjectEjectToWindowClassA(var_string("wndclass"), lib, nullptr, !eject, mm);
		*/

		if (proc)
		{
			if (proc.is64bit() != is64bit)
				BOOST_THROW_EXCEPTION(ex_target_bit_mismatch() << e_pid(proc.id()));

			if (wii)
			{
				proc.resume();
				proc.waitForInputIdle();
			}


			if (vars.count("inject"))
			{
				for (const Library& lib : vars["inject"].as<vector<path>>())
				{
					if (mm)
						proc.mapRemoteModule(lib, verbose);
					else
						proc.inject(lib, verbose);
				}
			}

			if (vars.count("eject"))
			{
				for (const Library& lib : vars["eject"].as<vector<path>>())
					proc.eject(lib);
			}

			if (!wii)
				proc.resume();

			if (vars.count("print-pid"))
				cout << proc.id() << endl;

			if (vars.count("wait-for-exit"))
				proc.wait();

			if (vars.count("kill-on-exit"))
				proc.kill();
		}
	}
	catch (const boost::exception& e)
	{
		cerr << boost::diagnostic_information(e);
		throw;
	}
	catch (const exception& e)
	{
		cerr << "non-boost exception caught: " << e.what() << endl;
		throw;
	}
	catch (...)
	{
		cerr << "exception of unknown type" << endl;
		throw;
	}

	return 0;
}
