#pragma once

#define _WIN32_WINNT _WIN32_WINNT_WIN7
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <vector>

#if !defined(__cpp_inline_variables)
#error
#endif

namespace sha
{
	class sha1
	{
		BCRYPT_HASH_HANDLE m_hash;

		std::vector<std::uint8_t> m_object;

	public:
		sha1();
		~sha1();

		constexpr inline static std::size_t HASH_SIZE = 20;

		void input(const std::uint8_t * data, std::size_t size);
		void result(std::uint8_t(&digest)[HASH_SIZE]);
	};
}
