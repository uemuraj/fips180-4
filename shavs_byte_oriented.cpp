//
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing#shavs
//

#include <cstdint>
#include <istream>
#include <vector>

using message = std::vector<std::uint8_t>;
using digest = std::vector<std::uint8_t>;

std::vector<std::pair<message, digest>> getShaTestVectors(std::istream & responsefile);
std::vector<std::uint8_t> to_binary(const std::string & hex);

#include <algorithm>
#include <iostream>
#include <sstream>
#include <cassert>

#include <sha.h>

int main()
{
	auto shavs = getShaTestVectors(std::cin);

	for (const auto & shav : shavs)
	{
		// TODO assert() でなく適当な例外を挙げてテストを続行するように

		std::uint8_t digest[sha::sha1::HASH_SIZE]{};

		auto & [msg, md] = shav;
		sha::sha1 hash;
		hash.input(msg.data(), msg.size());
		hash.result(digest);

		assert(std::equal(md.cbegin(), md.cend(), digest));
	}

	return 0;
}

std::vector<std::pair<message, digest>> getShaTestVectors(std::istream & responsefile)
{
	std::vector<std::pair<message, digest>> shavs;

	std::pair<message, digest> shav;

	std::string buff, key, delim, value;

	std::size_t len{};

	while (std::getline(responsefile, buff))
	{
		std::istringstream line(buff);

		line >> key, line >> delim, line >> value;

		if (line.fail() || delim.compare("=") != 0)
		{
			continue;
		}

		if (key.compare("Len") == 0)
		{
			len = std::stoul(value);
		}

		if (key.compare("Msg") == 0 && len > 0)
		{
			shav.first = to_binary(value);
		}

		if (key.compare("MD") == 0)
		{
			shav.second = to_binary(value);
		}

		if (!shav.second.empty())
		{
			shavs.emplace_back(std::move(shav));
		}
	}

	return shavs;
}

std::vector<std::uint8_t> to_binary(const std::string & hex)
{
	static const std::string letters{ "0123456789abcdef" };

	std::vector<std::uint8_t> buff;

	for (auto it = hex.cbegin(); it != hex.cend();)
	{
		auto hi = letters.find(*it++);
		auto lo = letters.find(*it++);

		assert(0 <= hi && hi <= 15);
		assert(0 <= lo && lo <= 15);

		buff.push_back((std::uint8_t)((hi << 4) | lo));
	}

	return buff;
}
