#pragma once

#include <cstdint>
#include <array>
#include <memory>

#if !defined(__cpp_inline_variables)
#error
#endif

// TODO �R���p�C�����Ɏg�p��������͌��܂��Ă���͂��Ȃ̂ŁA���z�֐��ȊO�̃C���^�t�F�[�X�ɂ���

namespace sha
{
	class sha1
	{
	public:
		constexpr inline static std::size_t HASH_SIZE = 20;

		virtual void input(const std::uint8_t * data, std::size_t size) = 0;

		virtual void result(std::array<std::uint8_t, HASH_SIZE> & digest) = 0;

		virtual ~sha1() = default;
	};

	std::unique_ptr<sha1> make_sha1();
}
