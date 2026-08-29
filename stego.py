import os
import random

# ============================================================
# CONFIGURAÇÃO
# ============================================================

MAGIC_HEADER = 0xABCD
MAGIC_INICIO = 0xD3A7

HEADER_BYTES = 20
INICIO_BYTES = 8

MENSAGEM = b"Hello, World!"

CARRIER = b"\b\t\n\v\f\r\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037 !\"#$%&'()*+,-./01234567" # None for random carrier 
CARRIER_TAMANHO = 80 # Only used if CARRIER is None


# ============================================================
# BITS
# ============================================================

def escrever_bits(carrier, pos, valor, bits):
    for word in range(bits // 2):
        carrier[pos + word] = (carrier[pos + word] & 0b11111100) | (valor & 0b11)
        valor >>= 2

    return pos + bits // 2


def ler_bits(carrier, pos, bits):
    valor = 0

    for word in range(bits // 2):
        bits_recuperados = carrier[pos + word] & 0b11
        valor |= bits_recuperados << (word * 2)

    return valor, pos + bits // 2


def esconder_bytes(carrier, pos, dados):
    for byte in dados:
        pos = escrever_bits(carrier, pos, byte, 8)

    return pos


def ler_bytes(carrier, pos, quantidade):
    dados = bytearray()

    for _ in range(quantidade):
        byte, pos = ler_bits(carrier, pos, 8)
        dados.append(byte)

    return bytes(dados), pos


# ============================================================
# CAPACIDADE
# ============================================================

def capacidade(carrier):
    """Retorna quantos bytes de mensagem cabem no carrier."""
    disponivel = len(carrier) - HEADER_BYTES - INICIO_BYTES
    return max(0, disponivel // 4)


# ============================================================
# CODIFICAÇÃO
# ============================================================

def codificar(carrier, mensagem, seq, total):
    buf = bytearray(carrier)

    # Header
    pos = escrever_bits(buf, 0, MAGIC_HEADER, 16)
    pos = escrever_bits(buf, pos, total, 8)
    pos = escrever_bits(buf, pos, seq, 8)
    escrever_bits(buf, pos, len(mensagem), 8)

    # Escolhe onde ficará o marcador
    max_inicio = len(buf) - INICIO_BYTES - len(mensagem) * 4
    inicio = random.randint(HEADER_BYTES, max_inicio)

    # Marcador + mensagem
    escrever_bits(buf, inicio, MAGIC_INICIO, 16)
    esconder_bytes(buf, inicio + INICIO_BYTES, mensagem)

    return bytes(buf)


# ============================================================
# DECODIFICAÇÃO
# ============================================================

def decodificar(carrier):
    if len(carrier) < HEADER_BYTES:
        return None

    # Lê o header
    magic, pos = ler_bits(carrier, 0, 16)
    total, pos = ler_bits(carrier, pos, 8)
    seq, pos = ler_bits(carrier, pos, 8)
    tamanho, pos = ler_bits(carrier, pos, 8)

    # Validação
    if magic != MAGIC_HEADER:
        return None

    if total == 0 or seq >= total or tamanho == 0:
        return None

    # Procura o marcador
    inicio = None

    for p in range(HEADER_BYTES, len(carrier) - INICIO_BYTES + 1):
        marcador, _ = ler_bits(carrier, p, 16)

        if marcador == MAGIC_INICIO:
            inicio = p
            break

    if inicio is None:
        return None

    # Verifica se a mensagem cabe
    pos = inicio + INICIO_BYTES

    if pos + tamanho * 4 > len(carrier):
        return None

    mensagem, _ = ler_bytes(carrier, pos, tamanho)

    return {
        "seq": seq,
        "total": total,
        "mensagem": mensagem
    }


# ============================================================
# FRAGMENTAÇÃO
# ============================================================

def codificar_mensagem(mensagem, carrier):
    cap = capacidade(carrier)

    fragmentos = [
        mensagem[i:i + cap]
        for i in range(0, len(mensagem), cap)
    ]

    total = len(fragmentos)

    return [
        codificar(carrier, fragmento, seq, total)
        for seq, fragmento in enumerate(fragmentos)
    ]


# ============================================================
# REMONTAGEM
# ============================================================

def remontar(payloads):
    fragmentos = {}
    total = None

    for payload in payloads:
        dados = decodificar(payload)

        if dados is None:
            return None

        if total is None:
            total = dados["total"]
        elif dados["total"] != total:
            return None

        fragmentos[dados["seq"]] = dados["mensagem"]

    if total is None or len(fragmentos) != total:
        return None

    return b"".join(fragmentos[i] for i in range(total))


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    carrier = CARRIER or os.urandom(CARRIER_TAMANHO)

    print("=" * 60)
    print("ESTEGANOGRAFIA")
    print("=" * 60)

    print(f"Carrier:     {len(carrier)} bytes")
    print(f"Capacidade:  {capacidade(carrier)} bytes/fragmento")
    print(f"Mensagem:    {MENSAGEM!r}")
    print(f"Tamanho:     {len(MENSAGEM)} bytes")

    # Carrier original
    print()
    print("Carrier original:")
    print(f"  HEX:   {carrier.hex(' ')}")
    print(f"  ASCII: {''.join(chr(b) if 32 <= b <= 126 else '.' for b in carrier)}")

    # Codificação
    payloads = codificar_mensagem(MENSAGEM, carrier)

    print()
    print(f"Fragmentos: {len(payloads)}")

    for i, payload in enumerate(payloads):

        dados = decodificar(payload)

        print()
        print("-" * 60)
        print(f"FRAGMENTO {i}")
        print("-" * 60)

        if dados is None:
            print("[ERRO] Payload inválido")
            continue

        print(f"Magic:       0x{MAGIC_HEADER:04X}")
        print(f"Total:       {dados['total']}")
        print(f"Seq:         {dados['seq']}")
        print(f"Tamanho:     {len(dados['mensagem'])} bytes")
        print(f"Mensagem:    {dados['mensagem']!r}")

        print()
        print("Payload:")
        print(f"  HEX:   {payload.hex(' ')}")

    # Remontagem fora de ordem
    print()
    print("-" * 60)
    print("REMONTAGEM")
    print("-" * 60)

    recuperada = remontar(payloads[::-1])

    if recuperada == MENSAGEM:
        print("[OK] Mensagem recuperada corretamente")
        print(f"     {recuperada!r}")
    else:
        print("[ERRO] Mensagem diferente")
        print(f"     Esperado: {MENSAGEM!r}")
        print(f"     Recebido: {recuperada!r}")

    print("=" * 60)

