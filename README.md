# DataHiding_Project

> **Steganografia via ICMP** — esconde dados arbitrários (texto ou arquivo) nos 2 bits menos significativos (LSBs) do payload de pacotes Echo Reply, transmitidos entre dois containers Docker numa rede isolada.

---

## Sumário

1. [Visão Geral](#visão-geral)
2. [Estrutura do Repositório](#estrutura-do-repositório)
3. [Arquitetura (Docker)](#arquitetura-docker)
4. [Camadas do Protocolo](#camadas-do-protocolo)
5. [Técnica LSB — como cada byte é alterado](#técnica-lsb--como-cada-byte-é-alterado)
6. [Carrier (portador)](#carrier-portador)
7. [Formato do Header Stego](#formato-do-header-stego)
8. [Exemplo completo byte-a-byte — mensagem](#exemplo-completo-byte-a-byte--mensagem-hi) `"Hi!"`
9. [Formato File Payload](#formato-file-payload)
10. [Fragmentação](#fragmentação)
11. [Camada ICMP](#camada-icmp)
12. [Fluxo do Codificador](#fluxo-do-codificador)
13. [Fluxo do Decodificador](#fluxo-do-decodificador)
14. [Setup e Uso](#setup-e-uso)

---



## Visão Geral

O projeto oculta uma mensagem ou arquivo inteiro dentro do campo de dados (`payload`) de pacotes ICMP Echo Reply. A técnica usada é **LSB steganography de 2 bits**: os 2 bits menos significativos de cada byte do portador (carrier) são substituídos pelos bits da informação secreta. O restante dos bits fica intacto, de modo que o pacote continua parecendo tráfego ICMP normal.

```
Mensagem/arquivo
      │
      ▼
 Fragmentação
      │
      ▼  ← fragmento + header stego → 2 LSBs de cada byte do carrier
 Codificação LSB
      │
      ▼
Payload ICMP (parece dado ordinário)
      │
      ▼  ← rede Docker isolada (10.0.1.0/24)
 Transmissão
      │
      ▼
Decodificação LSB
      │
      ▼
 Remontagem
      │
      ▼
Mensagem/arquivo recuperado
```

---



## Estrutura do Repositório

```
DataHiding_Project/
├── compose.yaml          # Orquestração Docker (rede + serviços)
├── Dockerfile.envia      # Container do cliente (sender)
├── Dockerfile.recebe     # Container do servidor (receiver)
├── .env.example          # Variáveis de ambiente configuráveis
├── protocolo.txt         # Especificação original do protocolo
├── input/                # Monte o arquivo a enviar aqui
└── src/
    ├── client.py         # Ponto de entrada do sender
    ├── server.py         # Ponto de entrada do receiver
    ├── stego.py          # Núcleo: codificação/decodificação LSB
    ├── icmp.py           # Criação e parsing de pacotes ICMP raw
    └── file_payload.py   # Empacotamento de arquivos na mensagem
```

---



## Arquitetura (Docker)

```
┌────────────────────────────────────────────────────────┐
│  Rede Docker bridge  10.0.1.0/24                       │
│                                                        │
│  ┌─────────────────────┐    ICMP Echo Reply            │
│  │  envia (sender)     │ ─────────────────────────►   │
│  │  10.0.1.3           │                               │
│  │  client.py          │ ◄─────────────────────────   │
│  │  ./input  montado   │    (não há reply real;        │
│  └─────────────────────┘     o payload stego           │
│                               vai no Echo Reply)       │
│  ┌─────────────────────┐                               │
│  │  recebe (receiver)  │                               │
│  │  10.0.1.2           │                               │
│  │  server.py          │                               │
│  │  ./output montado   │                               │
│  └─────────────────────┘                               │
└────────────────────────────────────────────────────────┘
```

Ambos os containers precisam de `CAP_NET_RAW` e `CAP_NET_ADMIN` para criar **raw sockets** ICMP.

---



## Camadas do Protocolo

```
┌──────────────────────────────────────────────────┐
│  Camada 4 — Conteúdo                             │
│  Texto puro  OU  File Payload (magic + nome + dados)│
├──────────────────────────────────────────────────┤
│  Camada 3 — Stego                                │
│  Header (MAGIC_HEADER, total, seq, size)          │
│  + Start Marker (MAGIC_START)                    │
│  + Fragmento da mensagem                         │
│  → tudo escondido nos 2 LSBs do carrier          │
├──────────────────────────────────────────────────┤
│  Camada 2 — ICMP                                 │
│  Echo Reply (type=0)  |  ICMP ID  |  seq ICMP    │
│  payload = carrier modificado                    │
├──────────────────────────────────────────────────┤
│  Camada 1 — Raw Socket / IP                      │
│  socket.AF_INET, SOCK_RAW, IPPROTO_ICMP          │
└──────────────────────────────────────────────────┘
```

---



## Técnica LSB — como cada byte é alterado

Cada byte do carrier tem 8 bits. Os **6 bits mais significativos são preservados** e apenas os **2 LSBs** são sobrescritos com 2 bits da informação secreta.

```
Byte original do carrier:
  ┌───┬───┬───┬───┬───┬───┬───┬───┐
  │ 7 │ 6 │ 5 │ 4 │ 3 │ 2 │ 1 │ 0 │   bit position
  └───┴───┴───┴───┴───┴───┴───┴───┘
    ← preservados (AND 0xFC) →   ↑↑
                                 └┴── sobrescritos com 2 bits do segredo

Operação (write_bits):
  carrier[i] = (carrier[i] & 0b11111100) | (bits_secretos & 0b11)
```

Para esconder **1 byte** (8 bits) de informação são necessários **4 bytes** do carrier (2 bits × 4 = 8 bits).

```
Escondendo o byte 0x48 ('H') = 0100 1000:

  Bit-pair 0 (bits 0-1):  00   → carrier[0] & 0xFC | 00
  Bit-pair 1 (bits 2-3):  10   → carrier[1] & 0xFC | 10
  Bit-pair 2 (bits 4-5):  00   → carrier[2] & 0xFC | 00
  Bit-pair 3 (bits 6-7):  01   → carrier[3] & 0xFC | 01

A ordem é do LSB para o MSB (little-endian de bits):
  0x48 = 0100 1000
  pair 0: 0x48 & 0b11         = 00  (bits 0-1)
  pair 1: (0x48 >> 2) & 0b11  = 10  (bits 2-3)
  pair 2: (0x48 >> 4) & 0b11  = 00  (bits 4-5)
  pair 3: (0x48 >> 6) & 0b11  = 01  (bits 6-7)

Reconstrução (read_bits):
  value  = 00 << 0 = 0x00
  value |= 10 << 2 = 0x08   → 0x08
  value |= 00 << 4 = 0x00   → 0x08
  value |= 01 << 6 = 0x40   → 0x48 ✓
```

---



## Carrier (portador)

O carrier é uma sequência **fixa de 48 bytes** (valores 0x08–0x37), definida em `client.py`:

```
Posição:  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
Valor:    08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17

Posição:  10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
Valor:    18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27

Posição:  20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F
Valor:    28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37
```

Os LSBs originais repetem o padrão `00 01 10 11 00 01 10 11 …`, o que torna as alterações mínimas e difíceis de detectar visualmente.

### Capacidade por fragmento

```
Carrier:        48 bytes
Header stego:   28 bytes do carrier  (28 × 2 bits = 56 bits de dados)
Start marker:    8 bytes do carrier  ( 8 × 2 bits = 16 bits de dados)
Disponível:     48 - 28 - 8 = 12 bytes do carrier
Bytes de mensagem por fragmento: 12 ÷ 4 = 3 bytes/fragmento
```

> Para um arquivo de 1 KB (1024 bytes) são necessários ≈ 342 fragmentos ICMP.

---



## Formato do Header Stego

O header é **sempre** escrito nas primeiras 28 posições do carrier (posições 0–27):

```
┌─────────────────┬────────┬─────────────────┬───────────────────────────┐
│ Campo           │ Bits   │ Bytes do carrier│ Descrição                 │
├─────────────────┼────────┼─────────────────┼───────────────────────────┤
│ MAGIC_HEADER    │ 16     │ 8  (pos  0– 7)  │ Assinatura: 0xABCD        │
│ total           │ 16     │ 8  (pos  8–15)  │ Número total de fragmentos│
│ seq             │ 16     │ 8  (pos 16–23)  │ Índice deste fragmento    │
│ size            │  8     │ 4  (pos 24–27)  │ Bytes de mensagem aqui    │
├─────────────────┼────────┼─────────────────┼───────────────────────────┤
│ TOTAL HEADER    │ 56     │ 28              │                           │
└─────────────────┴────────┴─────────────────┴───────────────────────────┘
```

Após o header, o **Start Marker** (MAGIC_START = 0xD3A7) é inserido em uma **posição aleatória** entre o byte 28 e o último byte que ainda cabe o marcador + mensagem:

```
max_start = len(carrier) - START_BYTES - len(fragment) × 4
          = 48 - 8 - (3 × 4)
          = 28   ← com carrier de 48 bytes e fragmento de 3 bytes,
                    só há uma posição possível: 28

┌────────────────────────────┬──────────────┬──────────────────────┐
│ Start Marker (MAGIC_START) │ Bits │ Bytes │ Posição no carrier   │
├────────────────────────────┼──────┼───────┼──────────────────────┤
│ 0xD3A7                     │ 16   │ 8     │ start … start+7      │
│ fragmento da mensagem      │ n×8  │ n×4   │ start+8 … start+8+n×4│
└────────────────────────────┴──────┴───────┴──────────────────────┘
```

A posição aleatória do start marker é a principal defesa do protocolo contra análise estatística: em carriers maiores, o receiver precisa **varrer** o carrier procurando o MAGIC_START.

---



## Exemplo completo byte-a-byte — mensagem `"Hi!"`



### Entrada


| Campo    | Valor                                |
| -------- | ------------------------------------ |
| Mensagem | `"Hi!"` = `0x48 0x69 0x21` (3 bytes) |
| total    | 1 fragmento                          |
| seq      | 0                                    |
| size     | 3                                    |
| start    | posição 28 (única possível)          |




### Carrier original vs. carrier modificado

```
Pos  Orig  Mod   Δ  Bin original  Bin modificado  Conteúdo escondido
───  ────  ────  ─  ────────────  ──────────────  ──────────────────────────────
                    [ HEADER — MAGIC_HEADER = 0xABCD (16 bits) ]
 00  0x08  0x09  +1  0000 1000    0000 1001      MAGIC_HEADER bits[0:2]  = 01
 01  0x09  0x0B  +2  0000 1001    0000 1011      MAGIC_HEADER bits[2:4]  = 11
 02  0x0A  0x08  -2  0000 1010    0000 1000      MAGIC_HEADER bits[4:6]  = 00
 03  0x0B  0x0B   0  0000 1011    0000 1011      MAGIC_HEADER bits[6:8]  = 11
 04  0x0C  0x0F  +3  0000 1100    0000 1111      MAGIC_HEADER bits[8:10] = 11
 05  0x0D  0x0E  +1  0000 1101    0000 1110      MAGIC_HEADER bits[10:12]= 10
 06  0x0E  0x0E   0  0000 1110    0000 1110      MAGIC_HEADER bits[12:14]= 10
 07  0x0F  0x0E  -1  0000 1111    0000 1110      MAGIC_HEADER bits[14:16]= 10
                    [ HEADER — total = 1 (16 bits) ]
 08  0x10  0x11  +1  0001 0000    0001 0001      total bits[0:2]  = 01
 09  0x11  0x10  -1  0001 0001    0001 0000      total bits[2:4]  = 00
 10  0x12  0x10  -2  0001 0010    0001 0000      total bits[4:6]  = 00
 11  0x13  0x10  -3  0001 0011    0001 0000      total bits[6:8]  = 00
 12  0x14  0x14   0  0001 0100    0001 0100      total bits[8:10] = 00
 13  0x15  0x14  -1  0001 0101    0001 0100      total bits[10:12]= 00
 14  0x16  0x14  -2  0001 0110    0001 0100      total bits[12:14]= 00
 15  0x17  0x14  -3  0001 0111    0001 0100      total bits[14:16]= 00
                    [ HEADER — seq = 0 (16 bits) ]
 16  0x18  0x18   0  0001 1000    0001 1000      seq bits[0:2]  = 00
 17  0x19  0x18  -1  0001 1001    0001 1000      seq bits[2:4]  = 00
 18  0x1A  0x18  -2  0001 1010    0001 1000      seq bits[4:6]  = 00
 19  0x1B  0x18  -3  0001 1011    0001 1000      seq bits[6:8]  = 00
 20  0x1C  0x1C   0  0001 1100    0001 1100      seq bits[8:10] = 00
 21  0x1D  0x1C  -1  0001 1101    0001 1100      seq bits[10:12]= 00
 22  0x1E  0x1C  -2  0001 1110    0001 1100      seq bits[12:14]= 00
 23  0x1F  0x1C  -3  0001 1111    0001 1100      seq bits[14:16]= 00
                    [ HEADER — size = 3 (8 bits) ]
 24  0x20  0x23  +3  0010 0000    0010 0011      size bits[0:2] = 11
 25  0x21  0x20  -1  0010 0001    0010 0000      size bits[2:4] = 00
 26  0x22  0x20  -2  0010 0010    0010 0000      size bits[4:6] = 00
 27  0x23  0x20  -3  0010 0011    0010 0000      size bits[6:8] = 00
                    [ START MARKER — MAGIC_START = 0xD3A7 (16 bits) @ pos 28 ]
 28  0x24  0x27  +3  0010 0100    0010 0111      MAGIC_START bits[0:2]  = 11
 29  0x25  0x25   0  0010 0101    0010 0101      MAGIC_START bits[2:4]  = 01
 30  0x26  0x26   0  0010 0110    0010 0110      MAGIC_START bits[4:6]  = 10
 31  0x27  0x26  -1  0010 0111    0010 0110      MAGIC_START bits[6:8]  = 10
 32  0x28  0x2B  +3  0010 1000    0010 1011      MAGIC_START bits[8:10] = 11
 33  0x29  0x28  -1  0010 1001    0010 1000      MAGIC_START bits[10:12]= 00
 34  0x2A  0x29  -1  0010 1010    0010 1001      MAGIC_START bits[12:14]= 01
 35  0x2B  0x2B   0  0010 1011    0010 1011      MAGIC_START bits[14:16]= 11
                    [ MENSAGEM — 'H' = 0x48 = 0100 1000 ]
 36  0x2C  0x2C   0  0010 1100    0010 1100      'H' bits[0:2] = 00
 37  0x2D  0x2E  +1  0010 1101    0010 1110      'H' bits[2:4] = 10
 38  0x2E  0x2C  -2  0010 1110    0010 1100      'H' bits[4:6] = 00
 39  0x2F  0x2D  -2  0010 1111    0010 1101      'H' bits[6:8] = 01
                    [ MENSAGEM — 'i' = 0x69 = 0110 1001 ]
 40  0x30  0x31  +1  0011 0000    0011 0001      'i' bits[0:2] = 01
 41  0x31  0x32  +1  0011 0001    0011 0010      'i' bits[2:4] = 10
 42  0x32  0x32   0  0011 0010    0011 0010      'i' bits[4:6] = 10
 43  0x33  0x31  -2  0011 0011    0011 0001      'i' bits[6:8] = 01
                    [ MENSAGEM — '!' = 0x21 = 0010 0001 ]
 44  0x34  0x35  +1  0011 0100    0011 0101      '!' bits[0:2] = 01
 45  0x35  0x34  -1  0011 0101    0011 0100      '!' bits[2:4] = 00
 46  0x36  0x36   0  0011 0110    0011 0110      '!' bits[4:6] = 10
 47  0x37  0x34  -3  0011 0111    0011 0100      '!' bits[6:8] = 00
```

**Resultado:** 37 dos 48 bytes foram modificados. A variação máxima em qualquer byte é ±3 (somente os 2 LSBs mudam — de 0 a 3).

### Carrier modificado (hex dump)

```
Antes:  08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17
Depois: 09 0b 08 0b 0f 0e 0e 0e 11 10 10 10 14 14 14 14

Antes:  18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27
Depois: 18 18 18 18 1c 1c 1c 1c 23 20 20 20 27 25 26 26

Antes:  28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37
Depois: 2b 28 29 2b 2c 2e 2c 2d 31 32 32 31 35 34 36 34
```



### Como o receiver recria 'H' a partir dos bytes 36–39

```
carrier[36] = 0x2C  → LSBs = 00  → pair 0
carrier[37] = 0x2E  → LSBs = 10  → pair 1
carrier[38] = 0x2C  → LSBs = 00  → pair 2
carrier[39] = 0x2D  → LSBs = 01  → pair 3

Reconstrução:
  value  = 00          =  0x00
  value |= 10 << 2     =  0x08
  value |= 00 << 4     =  0x08
  value |= 01 << 6     =  0x48  → 'H' ✓
```

---



## Formato File Payload

Quando o modo arquivo está ativo (`FILE_PATH` definido), a mensagem secreta **não é o conteúdo bruto do arquivo**, mas sim um payload com cabeçalho próprio definido em `file_payload.py`:

```
┌──────────────┬──────────────┬───────────────────────┬──────────────────┐
│ FILE_MAGIC   │ name_len     │ filename               │ file_data        │
│ 4 bytes      │ 2 bytes (BE) │ name_len bytes (UTF-8) │ resto do payload │
│ = \x1bFIL   │              │                        │                  │
└──────────────┴──────────────┴───────────────────────┴──────────────────┘
```



### Exemplo — enviando `foto.png` (100 bytes)

```
Byte  0-3:   1B 46 49 4C           ← FILE_MAGIC ('\x1bFIL')
Byte  4-5:   00 08                 ← name_len = 8 (big-endian)
Byte  6-13:  66 6F 74 6F 2E 70 6E 67  ← "foto.png" (8 bytes UTF-8)
Byte 14-113: <100 bytes do PNG>    ← conteúdo binário do arquivo
```

O receiver detecta o `FILE_MAGIC`, extrai o nome, e salva o conteúdo em `OUTPUT_DIR/foto.png`.

Payloads **sem** o magic `\x1bFIL` são tratados como texto puro (modo retrocompatível).

---



## Fragmentação

Como o carrier suporta apenas **3 bytes por fragmento**, mensagens maiores são automaticamente divididas:

```python
cap       = (len(carrier) - HEADER_BYTES - START_BYTES) // 4
fragments = [message[i:i+cap] for i in range(0, len(message), cap)]
total     = len(fragments)
# total máximo: 65 535 fragmentos (campo seq é de 16 bits)
```



### Exemplo — `"Ola, Mundo!"` (11 bytes, cap=3)

```
total = ceil(11 / 3) = 4 fragmentos

Frag 0: seq=0, total=4, size=3, data=b"Ola"
Frag 1: seq=1, total=4, size=3, data=b", M"
Frag 2: seq=2, total=4, size=3, data=b"und"
Frag 3: seq=3, total=4, size=2, data=b"o!"
```

Cada fragmento gera **um pacote ICMP independente**. O receiver armazena os fragmentos indexados por `seq` e só remonta quando todos chegam.

```
Payload 1: [0xABCD][total=4][seq=0][size=3] ... [0xD3A7]["Ola"]
Payload 2: [0xABCD][total=4][seq=1][size=3] ... [0xD3A7][", M"]
Payload 3: [0xABCD][total=4][seq=2][size=3] ... [0xD3A7]["und"]
Payload 4: [0xABCD][total=4][seq=3][size=2] ... [0xD3A7]["o!"]
```

Fragmentos podem **chegar fora de ordem**: o receiver ordena por `seq` antes de concatenar.

---



## Camada ICMP

O pacote ICMP final tem estrutura padrão (RFC 792):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────┬───────────────┼───────────────────────────────────┤
│  Type (1 B)   │  Code (1 B)   │         Checksum (2 B)            │
├───────────────┴───────────────┼───────────────────────────────────┤
│         ICMP ID (2 B)         │         Sequence (2 B)            │
├───────────────────────────────┴───────────────────────────────────┤
│      Payload = carrier modificado com dados escondidos (48 B)     │
└───────────────────────────────────────────────────────────────────┘

Type:     0 (Echo Reply) — imita resposta de ping
Code:     0
ICMP ID:  PID do processo % 65535  (identifica o sender)
Sequence: número do fragmento ICMP (diferente do seq stego)
Payload:  48 bytes — o carrier com os LSBs reescritos
```

Tamanho total do pacote (sem IP header): **8 bytes ICMP header + 48 bytes payload = 56 bytes**.
Com IP header (20 bytes): **76 bytes por datagrama**.

### Verificação de integridade

O receiver valida um pacote em três etapas:

1. **Tipo ICMP:** descarta tudo que não for `type == 0` (Echo Reply).
2. **Magic header:** lê os 28 primeiros bytes do carrier e verifica se os LSBs reconstroem `0xABCD`. Se não, descarta.
3. **Sanidade:** `total > 0`, `seq < total`, `size > 0`; caso contrário, descarta.
4. **Start marker:** varre posições do carrier a partir de `HEADER_BYTES` buscando `0xD3A7` nos LSBs. Se não encontrar, descarta.

---



## Fluxo do Codificador

```
                    CODIFICADOR
                         │
                         ▼
                 Dividir mensagem
                  em fragmentos
              (3 bytes por fragmento)
                         │
                         ▼
              Para cada fragmento:
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
       Criar cabeçalho         Escolher posição i
       m=0xABCD                (aleatória, entre
       total, seq, t           HEADER_BYTES e max_start)
             │                       │
             └───────────┬───────────┘
                         ▼
                 Esconder cabeçalho
                 nos 2 LSBs
                 (posições 0–27)
                         │
                         ▼
              Esconder MAGIC_START (0xD3A7)
              nos 2 LSBs na posição i
              (posições i … i+7)
                         │
                         ▼
              Esconder fragmento da mensagem
              nos 2 LSBs após o start marker
              (posições i+8 … i+8+size×4-1)
                         │
                         ▼
              Empacotar em ICMP Echo Reply
              e enviar via raw socket
```

---



## Fluxo do Decodificador

```
                    DECODIFICADOR
                         │
                         ▼
              Receber datagrama raw ICMP
                         │
                         ▼
              type == Echo Reply (0)?
                    /          \
                  não           sim
                   │             │
                descarta         ▼
                        Ler 2 LSBs posições 0–7
                        → reconstruir 16 bits
                                 │
                                 ▼
                        value == 0xABCD?
                           /         \
                         não          sim
                          │            │
                       descarta        ▼
                               Ler total (pos 8–15)
                               Ler seq   (pos 16–23)
                               Ler size  (pos 24–27)
                                         │
                                         ▼
                               Varrer carrier a partir
                               de HEADER_BYTES (28)
                               procurando 0xD3A7 nos LSBs
                                         │
                                         ▼
                               Ler size bytes a partir
                               de start + START_BYTES
                                         │
                                         ▼
                               Guardar fragmento:
                               received[seq] = payload
                                         │
                                         ▼
                             len(received) == total?
                                /             \
                              não              sim
                               │                │
                             espera             ▼
                                        Ordenar por seq
                                        Concatenar fragmentos
                                               │
                                               ▼
                                       Detectar FILE_MAGIC?
                                          /         \
                                        sim          não
                                         │            │
                                     Salvar         Imprimir
                                     arquivo        texto
```

---



## Setup e Uso



### Pré-requisitos

- Docker e Docker Compose instalados
- Linux (raw sockets ICMP exigem `CAP_NET_RAW`)



### Instalação

```bash
git clone https://github.com/BerWalker/DataHiding_Project.git
cd DataHiding_Project
cp .env.example .env
```



### Modo texto (padrão)

```bash
# Edite .env e deixe FILE_PATH vazio:
MESSAGE="Ola, Mundo!"
FILE_PATH=

docker compose up --build
```



### Modo arquivo

```bash
# Coloque o arquivo em ./input/
cp meu_arquivo.pdf ./input/

# Edite .env:
FILE_PATH=/input/meu_arquivo.pdf

docker compose up --build
# O arquivo recuperado aparecerá em ./output/
```



### Variáveis de ambiente (`.env`)


| Variável      | Default         | Descrição                                     |
| ------------- | --------------- | --------------------------------------------- |
| `FILE_PATH`   | `""`            | Caminho do arquivo dentro do container sender |
| `MESSAGE`     | `Hello, World!` | Texto a enviar (usado quando FILE_PATH vazio) |
| `SERVER_HOST` | `10.0.1.2`      | IP do receiver                                |
| `TIMEOUT`     | `120`           | Segundos sem pacotes antes de encerrar        |
| `OUTPUT_DIR`  | `/output`       | Diretório onde o receiver salva arquivos      |




### Saída esperada (sender)

```
============================================================
CLIENT — ENCODING
============================================================
Server:      10.0.1.2
Carrier:     48 bytes (fixed)
Capacity:    3 bytes/fragment
Payload:     <text: 'Ola, Mundo!'>
Fragments:   4

  [     1/4   25.0%]  → 10.0.1.2  |  56 B/packet  |  stego=0/4  |  frag=b'Ola'
  [     2/4   50.0%]  → 10.0.1.2  |  56 B/packet  |  stego=1/4  |  frag=b', M'
  [     3/4   75.0%]  → 10.0.1.2  |  56 B/packet  |  stego=2/4  |  frag=b'und'
  [     4/4  100.0%]  → 10.0.1.2  |  56 B/packet  |  stego=3/4  |  frag=b'o!'

[OK] 4 fragment(s) sent  —  11 bytes total
============================================================
```



### Saída esperada (receiver)

```
============================================================
SERVER — WAITING FOR FRAGMENTS
============================================================
Listening on  0.0.0.0  (timeout: 120s without packets)

  [RECV      1/4   25.0%]  from=10.0.1.3  |  stego=1/4  |  frag=b'Ola'
  [RECV      2/4   50.0%]  from=10.0.1.3  |  stego=2/4  |  frag=b', M'
  [RECV      3/4   75.0%]  from=10.0.1.3  |  stego=3/4  |  frag=b'und'
  [RECV      4/4  100.0%]  from=10.0.1.3  |  stego=4/4  |  frag=b'o!'

[OK] All 4 fragment(s) received — waiting for timeout...
[TIMEOUT] No more packets — ending reception

------------------------------------------------------------
REASSEMBLY
------------------------------------------------------------
[OK] 11 bytes reassembled
[TEXT] 'Ola, Mundo!'
============================================================
```

---



## Constantes do protocolo


| Constante           | Valor     | Localização       | Descrição                              |
| ------------------- | --------- | ----------------- | -------------------------------------- |
| `MAGIC_HEADER`      | 0xABCD    | `stego.py`        | Assinatura do header stego             |
| `MAGIC_START`       | 0xD3A7    | `stego.py`        | Marcador de início da mensagem         |
| `FILE_MAGIC`        | `\x1bFIL` | `file_payload.py` | Assinatura de payload de arquivo       |
| `HEADER_BYTES`      | 28        | `stego.py`        | Bytes do carrier usados pelo header    |
| `START_BYTES`       | 8         | `stego.py`        | Bytes do carrier usados pelo marker    |
| `ICMP_ECHO_REQUEST` | 8         | `icmp.py`         | Tipo ICMP de request                   |
| `ICMP_ECHO_REPLY`   | 0         | `icmp.py`         | Tipo ICMP de reply (usado pelo sender) |


