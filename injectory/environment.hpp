#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"

class Environment
{
	unordered_map<wstring, wstring> env;
	using const_iterator = unordered_map<wstring, wstring>::const_iterator;
	using size_type = unordered_map<wstring, wstring>::size_type;

public:
	void set(const wstring& key, const wstring& value)
	{
		env.emplace(key, value);
	}

	void set(const wstring& kv)
	{
		size_t eq = kv.find(L'=');
		if (eq != wstring::npos)
		{
			wstring k = kv.substr(0, eq);
			wstring v = kv.substr(eq + 1);
			set(k, v);
		}
		else
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("missing '=' in '" + to_string(kv) + "', unable to set environment variable"));
	}

	size_type unset(const wstring& key)
	{
		return env.erase(key);
	}

	optional<wstring> get(const wstring& key) const
	{
		if (count(key))
			return env.at(key);
		else
			return {};
	}

	optional<wstring> operator[](const wstring& key) const
	{
		return get(key);
	}



public:
	static Environment current()
	{
		Environment env;

		auto free = [](wchar_t* p) { FreeEnvironmentStringsW(p); };
		auto env_block = std::unique_ptr<wchar_t, decltype(free)>{
			GetEnvironmentStringsW(), free };
		// GetEnvironmentStringsW() doesn't seem to return environment variables without values, e.g. 'EXAMPLE='

		for (const wchar_t* e = env_block.get(); *e != L'\0'; )
		{
			wstring kv(e);
			try
			{
				env.set(kv);
			}
			catch (...)
			{
				BOOST_THROW_EXCEPTION(ex_injection() << e_text("missing '=' in '" + to_string(kv) + "', unable to get current environment"));
			}
			e += kv.length() + 1;
		}

		return env;
	}



public:
	size_type count(const wstring& key) const
	{
		return env.count(key);
	}

	size_type size() const
	{
		return env.size();
	}

	bool empty() const
	{
		return env.empty();
	}

	void clear()
	{
		env.clear();
	}

	const_iterator begin() const
	{
		return env.begin();
	}

	const_iterator end() const
	{
		return env.end();
	}
};
