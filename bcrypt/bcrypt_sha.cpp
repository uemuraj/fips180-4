#define _WIN32_WINNT _WIN32_WINNT_WIN7
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#pragma comment (lib, "bcrypt")

#include <sha.h>
#include <vector>
#include <cassert>
#include <system_error>

class ntstatus_error_category : public std::error_category
{
public:
	const char * name() const noexcept override
	{
		return "ntstatus error";
	}

	std::string message(int ev) const override
	{
		std::string msg;

		if (HMODULE source = ::LoadLibrary(TEXT("NTDLL.DLL")))
		{
			void * buffer{};

			constexpr DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE;

			if (::FormatMessageA(flags, source, ev, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) &buffer, 0, nullptr))
			{
				msg = (const char *) buffer;
			}

			::LocalFree(buffer);

			::FreeLibrary(source);
		}

		return msg;
	}
};

class bcrypt_algorithm
{
	BCRYPT_ALG_HANDLE m_algorithm;

public:
	bcrypt_algorithm(const wchar_t * id) : m_algorithm(nullptr)
	{
		if (auto status = ::BCryptOpenAlgorithmProvider(&m_algorithm, id, nullptr, 0))
		{
			throw std::system_error(status, ntstatus_error_category(), "BCryptOpenAlgorithmProvider()");
		}
	}

	~bcrypt_algorithm()
	{
		::BCryptCloseAlgorithmProvider(m_algorithm, 0);
	}

	operator BCRYPT_HANDLE() const
	{
		return m_algorithm;
	}

	bcrypt_algorithm(bcrypt_algorithm &) = delete;
	bcrypt_algorithm(bcrypt_algorithm &&) = delete;

	bcrypt_algorithm & operator=(bcrypt_algorithm &) = delete;
	bcrypt_algorithm & operator=(bcrypt_algorithm &&) = delete;
};

bcrypt_algorithm & bcrypt_sha1_algorithm()
{
	static bcrypt_algorithm algorithm(BCRYPT_SHA1_ALGORITHM);

	return algorithm;
}

class bcrypt_sha1 : public sha::sha1
{
	BCRYPT_HASH_HANDLE m_hash;

	std::vector<std::uint8_t> m_object;

public:
	bcrypt_sha1() : m_hash(nullptr)
	{
		auto & algorithm = bcrypt_sha1_algorithm();

		ULONG length{}, result{};

		if (auto status = ::BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, (PUCHAR) &length, sizeof(length), &result, 0))
		{
			throw std::system_error(status, ntstatus_error_category(), "BCryptGetProperty(BCRYPT_HASH_LENGTH)");
		}

		assert(length == sha::sha1::HASH_SIZE);

		if (auto status = ::BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR) &length, sizeof(length), &result, 0))
		{
			throw std::system_error(status, ntstatus_error_category(), "BCryptGetProperty(BCRYPT_OBJECT_LENGTH)");
		}

		m_object.resize(length);

		if (auto status = ::BCryptCreateHash(algorithm, &m_hash, &m_object[0], length, nullptr, 0, 0))
		{
			throw std::system_error(status, ntstatus_error_category(), "BCryptCreateHash()");
		}
	}

	~bcrypt_sha1()
	{
		::BCryptDestroyHash(m_hash);
	}

	void input(const std::uint8_t * data, std::size_t size) override
	{
		if (auto status = ::BCryptHashData(m_hash, const_cast<PUCHAR>(data), size, 0))
		{
			throw std::system_error(status, ntstatus_error_category(), "BCryptHashData()");
		}
	}

	void result(std::array<std::uint8_t, HASH_SIZE> & digest) override
	{
		if (auto status = ::BCryptFinishHash(m_hash, digest.data(), digest.size(), 0))
		{
			throw std::system_error(status, ntstatus_error_category(), "BCryptFinishHash()");
		}
	}
};
