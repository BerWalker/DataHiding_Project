import os
import random

# ============================================================
# CONFIGURAÇÃO
# ============================================================

MENSAGEM = b"Hello, World!"

CARRIER = b"\b\t\n\v\f\r\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037 !\"#$%&'()*+,-./01234567"  # None = gerar aleatório
CARRIER_TAMANHO = 80   # usado só se CARRIER for None

# ============================================================
# CONSTANTES DO PROTOCOLO
# ============================================================

# Número mágico que valida o início do header
MAGIC_HEADER = 0xABCD

# Marcador que indica onde a mensagem começa dentro do carrier
MAGIC_INICIO = 0xD3A71F42

# Tamanho fixo do header em bytes do carrier
# (magic 16b + total 8b + seq 8b + tamanho 8b) → 40 bits → 20 bytes carrier
HEADER_BYTES = 20

# Tamanho fixo do marcador de início em bytes do carrier
# (32 bits → 16 bytes carrier)
INICIO_BYTES = 16

# ============================================================
# FUNÇÕES DE BIT (núcleo do protocolo)
#
# Cada byte de dado é dividido em grupos de 2 bits e cada
# grupo é escondido nos 2 LSBs de um byte do carrier.
#
# Ex.: 0xAB = 10 10 10 11  →  ocupa 4 bytes do carrier
# ============================================================

def escrever_2bits(carrier: bytearray, pos: int, valor: int):
    """Escreve 2 bits nos 2 LSBs do carrier[pos]."""
    carrier[pos] = (carrier[pos] & 0b11111100) | valor

def ler_2bits(carrier: bytes, pos: int) -> int:
    """Lê os 2 LSBs do carrier[pos]."""
    return carrier[pos] & 0b11

def esconder_int(carrier: bytearray, pos: int, valor: int, bits: int) -> int:
    """
    Esconde um inteiro de N bits no carrier (2 bits por byte).
    Retorna a próxima posição livre.
    """
    n_bytes = (bits + 1) // 2
    for i in range(n_bytes):
        shift = bits - 2 * (i + 1)
        dois_bits = ((valor >> shift) if shift >= 0 else (valor << -shift)) & 0b11
        escrever_2bits(carrier, pos + i, dois_bits)
    return pos + n_bytes

def ler_int(carrier: bytes, pos: int, bits: int) -> tuple[int, int]:
    """
    Lê um inteiro de N bits escondido no carrier.
    Retorna (valor, próxima_posição).
    """
    n_bytes = (bits + 1) // 2
    valor = 0
    for i in range(n_bytes):
        valor = (valor << 2) | ler_2bits(carrier, pos + i)
    excesso = n_bytes * 2 - bits
    if excesso:
        valor >>= excesso
    return valor, pos + n_bytes

def esconder_bytes(carrier: bytearray, pos: int, dados: bytes) -> int:
    """Esconde uma sequência de bytes (cada byte ocupa 4 bytes do carrier)."""
    for byte in dados:
        pos = esconder_int(carrier, pos, byte, 8)
    return pos

def ler_bytes(carrier: bytes, pos: int, qtd: int) -> tuple[bytes, int]:
    """Lê 'qtd' bytes escondidos no carrier."""
    resultado = bytearray()
    for _ in range(qtd):
        byte, pos = ler_int(carrier, pos, 8)
        resultado.append(byte)
    return bytes(resultado), pos

# ============================================================
# CAPACIDADE
# ============================================================

def capacidade(carrier: bytes) -> int:
    """
    Quantos bytes de mensagem cabem em um carrier.

    Reservado: HEADER_BYTES + INICIO_BYTES
    Cada byte da mensagem ocupa 4 bytes do carrier.
    """
    disponivel = len(carrier) - HEADER_BYTES - INICIO_BYTES
    return max(0, disponivel // 4)

# ============================================================
# CODIFICAÇÃO (esconder mensagem no carrier)
#
# Layout do carrier codificado:
#
#   [pos 0]   HEADER  → magic(16b) + total(8b) + seq(8b) + tamanho(8b)
#   [pos aleatória]   INICIO  → marcador de 32 bits
#   [logo após]       MENSAGEM → bytes escondidos
#   [resto]   bytes originais do carrier (não modificados)
# ============================================================

def codificar(carrier: bytes, mensagem: bytes, seq: int, total: int) -> bytes:
    """Esconde um fragmento da mensagem em uma cópia do carrier."""
    buf = bytearray(carrier)

    # Escreve o header na posição 0
    pos = esconder_int(buf, 0,   MAGIC_HEADER,  16)
    pos = esconder_int(buf, pos, total,          8)
    pos = esconder_int(buf, pos, seq,            8)
    pos = esconder_int(buf, pos, len(mensagem),  8)
    # pos agora == HEADER_BYTES

    # Escolhe posição aleatória para o marcador de início
    max_inicio = len(buf) - INICIO_BYTES - len(mensagem) * 4
    inicio = random.randint(HEADER_BYTES, max_inicio)

    # Escreve marcador e mensagem
    esconder_int(buf,   inicio,                MAGIC_INICIO, 32)
    esconder_bytes(buf, inicio + INICIO_BYTES, mensagem)

    return bytes(buf)

# ============================================================
# DECODIFICAÇÃO (recuperar mensagem do carrier)
# ============================================================

def decodificar(carrier: bytes) -> dict | None:
    """
    Recupera um fragmento escondido no carrier.
    Retorna {"seq", "total", "mensagem"} ou None se inválido.
    """
    if len(carrier) < HEADER_BYTES:
        return None

    # Lê o header
    magic, pos = ler_int(carrier, 0,   16)
    total, pos = ler_int(carrier, pos,  8)
    seq,   pos = ler_int(carrier, pos,  8)
    tam,   pos = ler_int(carrier, pos,  8)

    if magic != MAGIC_HEADER or total == 0 or seq >= total or tam == 0:
        return None

    # Procura o marcador de início (varredura linear após o header)
    inicio = None
    for p in range(HEADER_BYTES, len(carrier) - INICIO_BYTES + 1):
        v, _ = ler_int(carrier, p, 32)
        if v == MAGIC_INICIO:
            inicio = p
            break

    if inicio is None:
        return None

    # Lê a mensagem logo após o marcador
    msg_pos = inicio + INICIO_BYTES
    if msg_pos + tam * 4 > len(carrier):
        return None

    mensagem, _ = ler_bytes(carrier, msg_pos, tam)
    return {"seq": seq, "total": total, "mensagem": mensagem}

# ============================================================
# FRAGMENTAÇÃO E REMONTAGEM
# ============================================================

def codificar_mensagem(mensagem: bytes, carrier: bytes) -> list[bytes]:
    """
    Divide e codifica a mensagem inteira.
    Retorna uma lista de payloads (um por fragmento).
    """
    cap   = capacidade(carrier)
    frags = [mensagem[i:i+cap] for i in range(0, len(mensagem), cap)]
    total = len(frags)
    return [codificar(carrier, frag, seq, total) for seq, frag in enumerate(frags)]

def remontar(payloads: list[bytes]) -> bytes | None:
    """
    Decodifica e remonta payloads (aceita qualquer ordem).
    Retorna a mensagem completa ou None se falhar.
    """
    fragmentos = {}
    total = None

    for payload in payloads:
        res = decodificar(payload)
        if res is None:
            return None
        if total is None:
            total = res["total"]
        elif res["total"] != total:
            return None
        fragmentos[res["seq"]] = res["mensagem"]

    if total is None or len(fragmentos) != total:
        return None

    return b"".join(fragmentos[i] for i in range(total))

# ============================================================
# MAIN
# ============================================================

def main():
    carrier = CARRIER if CARRIER is not None else os.urandom(CARRIER_TAMANHO)

    print(f"Carrier:    {len(carrier)} bytes")
    print(f"Capacidade: {capacidade(carrier)} bytes/fragmento")
    print(f"Mensagem:   {MENSAGEM!r} ({len(MENSAGEM)} bytes)")

    payloads = codificar_mensagem(MENSAGEM, carrier)
    print(f"Fragmentos: {len(payloads)}")

    # Testa remontagem fora de ordem
    recuperada = remontar(list(reversed(payloads)))

    print()
    if recuperada == MENSAGEM:
        print(f"[OK] Recuperada: {recuperada!r}")
    else:
        print(f"[ERRO] Esperado: {MENSAGEM!r}")
        print(f"[ERRO] Recebido: {recuperada!r}")

if __name__ == "__main__":
    main()