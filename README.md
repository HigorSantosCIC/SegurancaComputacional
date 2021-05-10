# Segurança Computacional - 2021/1

# Alunos:

- Higor Gabriel Azevedo Santos - 17/0012387
- Fernando Ferreira Cordeiro   - 17/0057950

# Gerador/Verificador de Assinaturas

Deve-se implementar um gerador e verificador de assinaturas RSA em arquivos. Assim, deve-se implementar um programa com as seguintes funcionalidades:

- [ ] Geração de chaves (1024 bits)

- [ ] Assinatura
    1. Cálculo de hashes (função de hash SHA-3)
    2. Assinatura da mensagem (cifração do hash)
    3. Formatação do resultado (caracteres especiais e informações para verificação)

- [ ] Verificação
  1. Parsing do documento assinado (de acordo com a formatação usada)
  2. Decifração da assinatura (decifração do hash)
  3. Verificação (cálculo e comparação do hash do arquivo)

## Instruções

Para compilar, basta está acessando o diretorio principal do programa e executar: 

```
make
```

Para inicializar o programa, basta executar o comando:

```
./seguranca.out
```