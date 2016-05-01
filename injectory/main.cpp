#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injectory/library.hpp"
#include "injectory/process.hpp"
#include "injectory/module.hpp"
#include "injectory/job.hpp"

#include <boost/algorithm/string.hpp>
namespace algo = boost::algorithm;
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#define VERSION "5.1.1-SNAPSHOT"

template <typename T>
po::typed_value<vector<T>, wchar_t>* wvector()
{
	return po::wvalue<vector<T>>()->multitoken()->default_value({}, "");
}

Process proc;

int main(int argc, char *argv[])
{
	po::variables_map vars;
	try
	{
		po::options_description desc;
		po::options_description targets("Targets");
		po::options_description options("Options");

		targets.add_options()
			("pid,p",		po::value<int>()->value_name("PID"),		"find process by id")
			("procname,n",	po::wvalue<wstring>()->value_name("NAME"),	"find process by name")
			("wndtitle,t",	po::wvalue<wstring>()->value_name("TITLE"),	"find process by window title")
			("wndclass,c",	po::wvalue<wstring>()->value_name("CLASS"),	"find process by window class, can be combined with --wndtitle")
			("launch,l",	po::wvalue<wstring>()->value_name("EXE"),	"launches the target in a new process")
			("args,a",		po::wvalue<wstring>()->value_name("STRING")->default_value(L"", ""),
																		"arguments for --launch:ed process")
		;
		options.add_options()
			("inject,i",	wvector<wstring>()->value_name("DLL..."),	"inject libraries before main")
			("injectw,I",	wvector<wstring>()->value_name("DLL..."),	"inject libraries when input idle")
			("map,m",		wvector<wstring>()->value_name("DLL..."),	"map file into target before main")
			("mapw,M",		wvector<wstring>()->value_name("DLL..."),	"map file into target when input idle")
			("eject,e",		wvector<wstring>()->value_name("DLL..."),	"eject libraries before main")
			("ejectw,E",	wvector<wstring>()->value_name("DLL..."),	"eject libraries when input idle\n")

			("print-own-pid",											"print the pid of this process")
			("print-pid",												"print the pid of the target process")
			("rethrow",													"rethrow exceptions")
			("vs-debug-workaround",									  	"workaround for threads left suspended when debugging with"
																		" visual studio by resuming all threads for 2 seconds")

			("dbgpriv",												  	"set SeDebugPrivilege")
			("wait-for-exit",											"wait for the target to exit before exiting")
			("kill-on-exit",											"kill the target when exiting\n")

			("verbose,v",												"")
			("version",													"display version information and exit")
			("help",													"display help message and exit")
			//("Address of library (ejection)")
			//("a process (without calling LoadLibrary)")
			//("listmodules",									"dump modules associated with the specified process id")
		;
		desc.add(targets);
		desc.add(options);

		po::store(po::parse_command_line(argc, argv, desc), vars);
		po::notify(vars);

		if (vars.count("help"))
		{
			cout << "usage: injectory TARGET [OPTION]..." << endl
			     << "inject DLL:s into processes" << endl
			     << endl
			     << "Examples:" << endl
			     << "  injectory --launch a.exe --map b.dll --args \"1 2 3\"" << endl
			     << "  injectory --pid 12345 --inject b.dll --wait-for-exit" << endl
			     << desc << endl;
			return 0;
		}
		
		if (vars.count("version"))
		{
			cout << "injectory " << VERSION << endl
				 << "project home: https://github.com/blole/injectory" << endl;
			return 0;
		}

		if (vars.count("print-own-pid"))
			cout << Process::current.id() << endl;

		if (vars.count("dbgpriv"))
			Process::current.enablePrivilege(L"SeDebugPrivilege");

		bool verbose = vars.count("verbose") > 0;

		if (vars.count("pid"))
		{
			int pid = vars["pid"].as<int>();
			proc = Process::open(pid);
			proc.suspend();
		}
		else if (vars.count("procname"))
		{
			wstring name = vars["procname"].as<wstring>();
			proc = Process::findByExeName(name);
			proc.suspend();
		}
		else if (vars.count("wndtitle") || vars.count("wndclass"))
		{
			wstring wndtitle;
			wstring wndclass;
			if (vars.count("wndtitle")) wndtitle = vars["wndtitle"].as<wstring>();
			if (vars.count("wndclass")) wndclass = vars["wndclass"].as<wstring>();
			proc = Process::findByWindow(wndclass, wndtitle);
			proc.suspend();
		}
		else if (vars.count("launch"))
		{
			using boost::none;
			fs::path app = vars["launch"].as<wstring>();
			wstring args = vars["args"].as<wstring>();
			
			proc = Process::launch(app, args, none, none, false, CREATE_SUSPENDED).process;
		}
		else
			throw po::error("missing target (--pid, --procname, --wndtitle, --wndclass or --launch)");

		if (proc)
		{
			auto& inject = vars["inject"].as<vector<wstring>>();
			auto& map = vars["map"].as<vector<wstring>>();
			auto& eject = vars["eject"].as<vector<wstring>>();
			auto& injectw = vars["injectw"].as<vector<wstring>>();
			auto& mapw = vars["mapw"].as<vector<wstring>>();
			auto& ejectw = vars["ejectw"].as<vector<wstring>>();

			bool anyInjections = !(inject.empty() && map.empty() && eject.empty() && injectw.empty() && mapw.empty() && ejectw.empty());

			if (anyInjections && (proc.is64bit() != is64bit))
				BOOST_THROW_EXCEPTION(ex_target_bit_mismatch() << e_proc(proc));

			Job job;
			if (vars.count("kill-on-exit"))
			{
				job = Job::create();
				job.assignProcess(proc);
				JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
				jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
				job.setInfo(JobObjectExtendedLimitInformation, jeli);
			}

			for (const Library& lib : inject)	proc.inject(lib, verbose);
			for (const Library& lib : map)		proc.mapRemoteModule(lib, verbose);
			for (const Library& lib : eject)	proc.getInjected(lib).eject();

			proc.resume();
			if (!injectw.empty() || !mapw.empty() || !ejectw.empty())
				proc.waitForInputIdle(5000);

			for (const Library& lib : injectw)	proc.inject(lib, verbose);
			for (const Library& lib : mapw)		proc.mapRemoteModule(lib, verbose);
			for (const Library& lib : ejectw)	proc.getInjected(lib).eject();

			if (vars.count("vs-debug-workaround"))
			{
				//resume threads that may have been left suspended when debugging with visual studio
				for (int i = 0; i < 20; i++)
				{
					proc.wait(100);
					proc.resumeAllThreads();
				}
			}

			if (vars.count("print-pid"))
				cout << proc.id() << endl;

			if (vars.count("wait-for-exit"))
				proc.wait();

			if (vars.count("kill-on-exit"))
				proc.kill();
		}
	}
	catch (const po::error& e)
	{
		cerr << "injectory: " << e.what() << endl;
		cerr << "Try 'injectory --help' for more information." << endl;

		if (vars.count("rethrow")) throw; else return 1;
	}
	catch (const std::exception& e)
	{
		const boost::exception* be = boost::exception_detail::get_boost_exception(&e);
		if (be && !algo::starts_with(boost::diagnostic_information_what(*be), "Throw location unknown"))
			cerr << "injectory: " << boost::diagnostic_information_what(*be);
		else
			cerr << "injectory: " << e.what() << endl;
		if (vars.count("rethrow")) throw; else return 1;
	}
	catch (...)
	{
		cerr << "injectory: unkown exception" << endl;
		if (vars.count("rethrow")) throw; else return 1;
	}

	return 0;
}
