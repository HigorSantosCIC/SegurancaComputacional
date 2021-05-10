#pragma once

#include <string>
#include <vector>

#include "hash.h"

// R(x,k,n) = x^k (mod n)
class RSA {
 public:
  RSA() = default;

  std::pair<PublicKey, PrivateKey> create_key_pair();

  // Enc(m; pubK) = R(OAEP-pre(m),pubK)
  big_int encryptMessage(const PublicKey& public_key, const std::string& message);

  // Dec(c; privK) = OAEP-post(R(c,privK))
  std::string decryptMessage(const PrivateKey& private_key, const big_int& cipher_text);

  // Sign(m; privK) = R(H(m),privK)
  big_int digitalSigning(const PrivateKey& private_key, const std::string& m);

  // Ver(m; s; pubK) = R(s,pubK) == H(m)
  bool verifySignature(const PublicKey& public_key, const big_int& signature,
                       const std::string& message_received);

 private:
  big_int X, Y;

  /***
   * OAEP-pre(m):
   *  r = random nonce
   *  X = (m || 00...0) XOR H(r) // pad m with zeros
   *  Y = r XOR H(X)
   *  output X || Y
   * */
  big_int OAEP_Encode(const std::string& original_message);

  /***
   * OAEP-post(m'):
   *  split m' into X || Y
   *  r = Y XOR H(X)
   *  (m || 00...0) = X XOR G(R)
   *  output m
   * */
  std::string OAEP_Decode(const std::string& decrypted_message);
};
