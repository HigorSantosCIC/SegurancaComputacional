#include "rsa.h"

#include <boost/archive/iterators/insert_linebreaks.hpp>
#include <boost/integer/mod_inverse.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/random.hpp>
#include <boost/random/independent_bits.hpp>

static boost::random::mt19937 base_gen(std::clock());

static inline big_int fastPower(const big_int &a, big_int b, const big_int &n)
{
  if (b == 0)
    return 1;

  big_int x = a, y = b, mod = n;
  big_int result = 1;

  while (y > 0)
  {
    if (y % 2 == 1)
      result = (result * x) % mod;
    x = (x * x) % mod;
    y /= 2;
  }

  return result;
}

std::pair<PublicKey, PrivateKey> RSA::create_key_pair()
{
  auto getPrimeN = []() {
    boost::random::independent_bits_engine<boost::random::mt11213b, 512, big_int> //n_bits_prime = 512;
        gen(base_gen);

    big_int num = gen();
    while (!miller_rabin_test(num, 25))
      num = gen();
  // Gerado um numero randomico de 512 bits que seja primo, o que garante isso eh o teste de miller
  // para primalidade, se o resultado for falso então n é definitivamente composto, 
  // enquanto se o resultado for verdadeiro então n é provavelmente primo. 
  // A probabilidade de declarar um n composto como primo provável é de no máximo 0,25 testeque
    return num;
  };

  // Gerar dois grandes primos aleatorios, p e q, de tamanhos aproximados tal que o produto entre eles n = p*q é o tamanho de bits necessario e.g. 1024 bits
  big_int p = getPrimeN(), q = getPrimeN();
  // Computando n = pq e ϕ=(p−1)(q−1)
  const big_int n = p * q, phi = (p - 1) * (q - 1);
  big_int e = getPrimeN(), d = boost::integer::mod_inverse(e, phi);
  ;

  // Computa o expoente secreto d, 1 < d < ϕ, tal que ed = 1 mod ϕ.
  while (!d)
  {
    // Escolher um inteiro e, 1 < e < ϕ tal que o MDC(e,ϕ) = 1
    // Escolhas comuns para o E sao 3, 5, 17, 257, 65537
    while (e >= phi && boost::math::gcd(e, phi) != 1)
      e = getPrimeN();
    d = boost::integer::mod_inverse(e, phi);
  }

  return {{n, e, p, q}, {n, d}};
}

big_int RSA::encryptMessage(const PublicKey &pk, const std::string &m)
{
  big_int cipher_text = fastPower(OAEP_Encode(m), pk.e, pk.n);

  return cipher_text;
}

std::string RSA::decryptMessage(const PrivateKey &pk, const big_int &c)
{
  auto dm = boost::lexical_cast<std::string>(fastPower(c, pk.d, pk.n));

  return OAEP_Decode(dm);
}

big_int RSA::OAEP_Encode(const std::string &m)
{
  boost::random::independent_bits_engine<boost::random::mt19937, 77, b_mp::uint256_t> gen(base_gen);

  std::string padding = m;

  const auto r = gen();

  big_int msg_byte;
  b_mp::import_bits(msg_byte, padding.begin(), padding.end(), 8);

  X = msg_byte ^ hash(r);
  Y = r ^ hash(X);

  return [&]() {
    std::ostringstream os;
    os << X << Y;
    return boost::lexical_cast<big_int>(os.str());
  }();
}

std::string RSA::OAEP_Decode(const std::string &m)
{
  const auto padding = [&]() -> std::string {
    //recupera a string aleatória como r = Y ⊕ H (X)
    const auto r = Y ^ hash(X), gr = hash(r);

    //recupere a mensagem binaria 8-bit como m = X ⊕ G (r)
    const big_int m_8bit = X ^ gr;

    std::string decrypt_message;
    b_mp::export_bits(m_8bit, std::back_inserter(decrypt_message), 8);

    return decrypt_message;
  }();

  return padding;
}

big_int RSA::digitalSigning(const PrivateKey &pk, const std::string &m)
{
  big_int signature = fastPower(hash(m), pk.d, pk.n);

  return signature;
}

bool RSA::verifySignature(const PublicKey &pk, const big_int &signature, const std::string &m)
{
  bool check = true;
  if (hash(m) != fastPower(signature, pk.e, pk.n))
    check = false;

  return check;
}
