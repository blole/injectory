#include "injectory/exception.hpp"
#include "injectory/process.hpp"
#include "injectory/library.hpp"
#include "injectory/api.hpp"
#include <boost/algorithm/string/trim.hpp>
#include <regex>
#include <set>

string formatMessage(DWORD messageId, DWORD flags, LPCVOID source, DWORD languageId, va_list* args)
{
	wchar_t* buf;
	FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | flags,
		source,
		messageId,
		languageId,
		(wchar_t*)&buf, //strange cast, but needed
		0,
		args);

	if (buf)
	{
		string message = std::to_string(buf);
		boost::algorithm::trim(message);
		LocalFree_Throwing(buf);
		return message;
	}
	else
		return "";
}

string GetLastErrorString(DWORD errcode)
{
	string message = formatMessage(errcode);

	if (message.empty())
		return "GetLastError()=" + to_string(errcode) + " but no info from FormatMessage()";
	else
		return message;
}

string GetNTStatusString(DWORD nt_status)
{
	return formatMessage(nt_status, FORMAT_MESSAGE_FROM_HMODULE, Module::ntdll().handle());
}


optional<string> try_get_process_name(const Process& proc)
{
	try { return proc.path().filename().string(); }
	catch (...) { return {}; }
}



namespace boost
{
	string to_string(const e_last_error& x)
	{
		return '[' + boost::error_info_name(x) + "] = " + to_string_stub(x.value()) + ", " + to_string_stub(GetLastErrorString(x.value())) + '\n';
	}
	string to_string(const e_nt_status& x)
	{
		return '[' + boost::error_info_name(x) + "] = " + to_string_stub(x.value()) + ", " + to_string_stub(GetNTStatusString(x.value())) + '\n';
	}
	string to_string(const e_process& x)
	{
		const Process& proc = x.value();
		return '[' + boost::error_info_name(x) + "] = " + (format("(%d) %s\n") % proc.id() % try_get_process_name(proc).value_or("error getting process name")).str();
	}
}



optional<string> throw_location(const boost::exception& be)
{
	const char* const* file = boost::get_error_info<boost::throw_file>(be);
	const int* line = boost::get_error_info<boost::throw_line>(be);
	const char* const* func = boost::get_error_info<boost::throw_function>(be);
	std::ostringstream ss;

	if (file)
	{
		ss << fs::path(*file).filename().string();
		if (line)
			ss << "(" << *line << ")";
	}
	if (file && func)
		ss << " ";
	if (func)
	{
		string func_ = *func;
		func_ = std::regex_replace(func_, std::regex("^.*?([^ <]+)(<.*>)?\\(.*\\).*$"), "$1()");
		ss << func_;
	}

	string s = ss.str();
	if (s.empty())
		return {};
	else
		return s;
}



typedef std::map<boost::exception_detail::type_info_, shared_ptr<boost::exception_detail::error_info_base>> error_info_map;

namespace
{
	struct BackdoorToErrorInfoMap
	{
		typedef error_info_map type;
	};
}
template <>
const error_info_map* boost::exception::get<BackdoorToErrorInfoMap>() const
{
	if (!data_.get())
		data_.adopt(new exception_detail::error_info_container_impl);

	if (auto b = dynamic_cast<const boost::exception_detail::error_info_container_impl*>(data_.get()))
		return reinterpret_cast<const BackdoorToErrorInfoMap::type*>(&b->info_);
	else
		return nullptr;
}
const error_info_map* get_error_info_map(const boost::exception& be)
{
	return be.get<BackdoorToErrorInfoMap>();
}

std::set<boost::exception_detail::type_info_> non_printing_error_types = {
	BOOST_EXCEPTION_STATIC_TYPEID(e_nt_status),
	BOOST_EXCEPTION_STATIC_TYPEID(e_last_error),
	BOOST_EXCEPTION_STATIC_TYPEID(boost::errinfo_api_function),
	BOOST_EXCEPTION_STATIC_TYPEID(boost::errinfo_nested_exception),
};

string diagnostic_information(const boost::exception& be)
{
	if (auto* info_ = get_error_info_map(be))
	{
		std::ostringstream ss;
		for (const auto& [k, v] : *info_)
		{
			if (non_printing_error_types.find(k) == non_printing_error_types.end())
				ss << v->name_value_string();
		}
		return ss.str();
	}
	return "error getting diagnostic_information from exception";
}

void print_exception(std::exception_ptr ep, const string& prefix, int level)
{
	std::ostringstream ss;

	if (!prefix.empty())
		ss << prefix << ": ";



	// print exception
	try
	{
		std::rethrow_exception(ep);
	}
	catch (const std::exception& e)
	{
		const boost::exception* be = boost::exception_detail::get_boost_exception(&e);
		if (be)
		{
			if (e.what() != string("Unknown exception"))
				ss << e.what() << endl;

			if (const char* const* api_function = boost::get_error_info<boost::errinfo_api_function>(*be))
				ss << *api_function << ": ";

			if (const DWORD* errcode = boost::get_error_info<e_last_error>(*be))
				ss << GetLastErrorString(*errcode) << endl;

			if (auto nt_status = boost::get_error_info<e_nt_status>(*be))
				ss << GetNTStatusString(*nt_status) << endl;
			
			//ss << "\n" << boost::diagnostic_information_what(*be) << "\n";
			if (optional<string> src = throw_location(*be))
				ss << "at " << *src << endl;

			ss << diagnostic_information(*be);
		}
		else
			ss << e.what() << endl;
	}
	catch (...)
	{
		ss << "unkown exception" << endl;
	}
	cerr << std::regex_replace(ss.str(), std::regex("^"), string(level, ' '));



	// print std or boost nested exception
	try
	{
		std::rethrow_exception(ep);
	}
	catch (const std::exception& e)
	{
		try
		{
			std::rethrow_if_nested(e);

			const boost::exception* be = boost::exception_detail::get_boost_exception(&e);
			if (be)
			{
				if (const boost::exception_ptr* nested = boost::get_error_info<boost::errinfo_nested_exception>(*be))
					boost::rethrow_exception(*nested);
			}
		}
		catch (...)
		{
			print_exception(std::current_exception(), "caused by", level + 1);
		}
	}
	catch (...) {}
}
