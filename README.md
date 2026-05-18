# Projeto de Extensao de Seguranca de Sistemas e Criptografia

---

## Introducao e justificativa

Este trabalho apresenta uma cifra de blocos simetrica criada para proteger arquivos com registros sensiveis da Inn Seguros. O algoritmo utiliza blocos de 32 bits, uma chave principal de 32 bits derivada de uma string informada pelo usuario e uma rede de substituicao e permutacao com oito rodadas.

A implementacao foi feita em Go, sem bibliotecas externas e sem bibliotecas de criptografia. O programa permite encriptar e decriptar arquivos por linha de comando.

## Descricao do algoritmo

O arquivo de entrada e lido em memoria e processado em blocos de 32 bits. Antes da cifragem, o programa adiciona uma etiqueta de verificacao de 32 bits calculada com a chave e o conteudo do arquivo. Em seguida, aplica padding para que o tamanho final seja multiplo de 4 bytes.

A chave textual do usuario e convertida em uma chave principal de 32 bits pela funcao `MasterKey`, baseada em operacoes XOR, multiplicacao modular e rotacoes. A partir dela, `DeriveSubkeys` gera oito subchaves de 32 bits. Cada subchave usa constantes de rodada e uma funcao xorshift para produzir valores diferentes.

Cada rodada de encriptacao executa:

1. Mistura com subchave por XOR.
2. Mistura modular reversivel com constante dependente da subchave e da rodada.
3. Substituicao de oito nibbles de 4 bits por uma S-box de 16 posicoes gerada a partir da subchave.
4. Permutacao dos 32 bits por uma tabela Fisher-Yates gerada a partir da subchave.

A decriptacao executa as mesmas etapas em ordem inversa: permutacao inversa, substituicao inversa, subtracao da mistura modular e XOR com a subchave da rodada.

## Modo de operacao

Para cifrar arquivos com mais de um bloco, foi usado um modo encadeado semelhante ao CBC. O primeiro bloco e combinado com um IV de 32 bits armazenado no cabecalho do arquivo cifrado. Cada bloco claro e combinado por XOR com o bloco cifrado anterior antes de entrar na cifra de bloco. Isso evita que blocos iguais de texto claro gerem blocos iguais de texto cifrado dentro do mesmo arquivo.

Formato do arquivo cifrado:

- `IS32`: cabecalho de identificacao.
- IV de 32 bits.
- blocos cifrados de 32 bits.

## Justificativa da quantidade de rodadas

O requisito minimo era de tres rodadas. Foram usadas oito rodadas para aumentar a difusao e o efeito avalanche, mantendo o custo computacional baixo porque cada bloco tem apenas 32 bits. Com oito rodadas, uma mudanca pequena na chave ou no texto claro atravessa repetidamente substituicoes nao lineares e permutacoes dependentes da chave.

## Efeito avalanche

O efeito avalanche ocorre quando uma pequena alteracao no texto claro ou na chave modifica muitos bits do texto cifrado. Neste algoritmo, isso e estimulado por tres mecanismos:

- XOR com subchaves diferentes a cada rodada.
- Mistura modular reversivel, que introduz propagacao por carregamento aritmetico.
- S-box dependente da chave, que muda a substituicao dos nibbles.
- Permutacao de bits dependente da chave, que espalha os bits alterados para novas posicoes.

O teste `TestAvalancheWithOneBitKeyChange` cifra o mesmo bloco com as chaves `A` e `@`, que diferem em 1 bit no codigo ASCII, e verifica uma distancia minima entre os textos cifrados.

## Alinhamento com o tamanho do bloco

O algoritmo usa padding no estilo PKCS: se faltam `n` bytes para completar um bloco de 4 bytes, sao adicionados `n` bytes com o valor `n`. Quando o texto claro ja esta alinhado, e adicionado um bloco completo com quatro bytes de valor `4`. Na decriptacao, o padding e validado e removido.

## Exemplo de uso

Encriptar:

```bash
go run . -mode encrypt -in entrada.txt -out cifrado.is32 -key "minha-chave"
```

Decriptar:

```bash
go run . -mode decrypt -in cifrado.is32 -out recuperado.txt -key "minha-chave"
```

Gerar rastreamento das rodadas para um bloco:

```bash
go run . -mode trace -in 0x494E4E21 -key A
```

## Exemplo parcial de rodada

Bloco inicial: `0x494E4E21`. Chave textual: `A`.

| Rodada | Subchave | Apos XOR | Apos mistura | Apos substituicao | Apos permutacao |
| --- | --- | --- | --- | --- | --- |
| 1 | `0x710A1893` | `0x384456B2` | `0x1A3133DA` | `0x42646652` | `0x1F2A0614` |
| 2 | `0x11E26E07` | `0x0EC86813` | `0xCF71F1AB` | `0x31841495` | `0x8C1E4818` |
| 3 | `0x18369DFE` | `0x9428D5E6` | `0xB08127EE` | `0xB0C48E11` | `0x802599D2` |
| 4 | `0x241D2160` | `0xA438B8B2` | `0xA90A8D5C` | `0x57153D98` | `0xBB2B01E9` |
| 5 | `0xE32D063B` | `0x580607D2` | `0x55540D5D` | `0x333EDA3A` | `0xC7EF4AB0` |
| 6 | `0x93E40893` | `0x540B4223` | `0x220911A2` | `0xBB04AA6B` | `0x3BD867A0` |
| 7 | `0xA35A68F2` | `0x98820F52` | `0x4D8A521E` | `0x7D4E3961` | `0xFC7EC150` |
| 8 | `0xCAB0B68C` | `0x36CE77DC` | `0xDF8ADDC7` | `0x9378992A` | `0x3095CD87` |

Texto cifrado final: `0x3095CD87`.

## Comparacao de avalanche com chaves que diferem em 1 bit

As chaves `A` e `@` diferem em apenas 1 bit na representacao ASCII:

- `A` = `0x41` = `01000001`
- `@` = `0x40` = `01000000`

Mesmo bloco inicial: `0x494E4E21`.

| Chave | Texto cifrado |
| --- | --- |
| `A` | `0x3095CD87` |
| `@` | `0x16AF2E6A` |

A distancia de Hamming entre os dois textos cifrados e de 18 bits em 32, isto e, a alteracao de 1 bit na chave modificou 56,25% do bloco cifrado.

## Referencias bibliograficas

STALLINGS, William. Criptografia e seguranca de redes: principios e praticas. Sao Paulo: Pearson.

MENEZES, Alfred J.; VAN OORSCHOT, Paul C.; VANSTONE, Scott A. Handbook of Applied Cryptography. Boca Raton: CRC Press, 1996.

SCHNEIER, Bruce. Applied Cryptography. 2. ed. New York: Wiley, 1996.
