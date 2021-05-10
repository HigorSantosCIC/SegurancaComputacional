#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <fstream>
#include <sstream>

#include "keys.h"

extern "C" {
  namespace sha3Extern {
    #include <cstring>

    using namespace std;

    #include "sha3.h"
  }  
}

namespace b_mp = boost::multiprecision;

template <typename T>
static inline big_int hash(const T& val) {
  std::ostringstream os;
  os << val;

  auto s = os.str();
  boost::erase_all(s, " ");

  const char* text = s.c_str();

  sha3Extern::ByteStream_t* msg = sha3Extern::ByteStream(strlen(text));
  sha3Extern::BytesFromChar(msg, text);
  sha3Extern::ByteStream_t* hash = sha3Extern::Sha3(msg, 256);

  std::vector<unsigned char> bytes;
  for (int i = 0; i < hash->len; ++i) {
    bytes.push_back(hash->bytes[i]);
  }

  big_int z;
  b_mp::import_bits(z, bytes.begin(), bytes.end(), 8);

  return z;
}

// Pecorre a string do final por inicio ate achar primeiro 0, se a string tiver zero no final, tem chance deessa função pular o 0 por causa do padding
