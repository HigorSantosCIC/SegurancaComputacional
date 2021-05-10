#include "keys.h"
#include "rsa.h"
using namespace std;

int main(void) {
  RSA rsa;

  ifstream f("message.txt");
  if (!f.is_open()) {
    throw invalid_argument("Não foi possivel abrir o arquivo");
  }
  const auto msg = string(istreambuf_iterator<char>(f),
                     istreambuf_iterator<char>());

  cout << "Messangem enviada por Ana: " << msg << "\n\n";

  //key1 = public key -- key2 = private key
  const auto& [key1, key2] = rsa.create_key_pair();
  const auto pk = make_pair(key1, key2);

  big_int cipher_text = rsa.encryptMessage(key1, msg);
  cout << "Mensagem criptografada RSA-OAEP: "  << hex << cipher_text << dec << "\n\n";

  const auto decrypted_message = rsa.decryptMessage(key2, cipher_text);
  cout << "Mensagem recebida por Bob: " << decrypted_message << "\n\n";

  // Sign(m; k) = R(m,k)
  big_int signature = rsa.digitalSigning(key2, msg);
  //Ver(m; s; K) = R(s,K) == m
  bool isvalid = rsa.verifySignature(key1, signature, decrypted_message);
  if (isvalid)
    cout << "Assinatura é válida!\n";
  else
    cout << "Assinatura é inválida!\n";

  return 0;
}
