#pragma once

#include <cstdint>
#include <array>
#include <memory>
#include <bcrypt.h>

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
		constexpr inline static std::size_t HASH_SIZE = 20;

		virtual void input(const std::uint8_t * data, std::size_t size) = 0;

		virtual void result(std::array<std::uint8_t, HASH_SIZE> & digest) = 0;

		virtual ~sha1() = default;
	};
}
