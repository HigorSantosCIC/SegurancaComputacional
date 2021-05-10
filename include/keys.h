#pragma once

#include <boost/multiprecision/cpp_int.hpp>

using big_int = boost::multiprecision::cpp_int;

struct PublicKey {
  big_int n, e, p, q;
};

struct PrivateKey {
  big_int n, d;
};
