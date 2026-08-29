# debugger.py
#
# Debugger para o protocolo de esteganografia.
#
# Uso:
#   python debugger.py
#
# O arquivo protocolo.py deve estar no mesmo diretório.
#
# Este debugger não altera o protocolo; ele apenas inspeciona
# e valida os dados produzidos por ele.

from stego import (
    MENSAGEM,
    CARRIER,
    CARRIER_TAMANHO,
    MAGIC_HEADER,
    MAGIC_INICIO,
    HEADER_BYTES,
    INICIO_BYTES,
    capacidade,
    codificar,
    codificar_mensagem,
    decodificar,
    esconder_int,
    ler_int,
)


# ============================================================
# CONFIGURAÇÃO DO DEBUGGER
# ============================================================

MOSTRAR_HEX = True
MOSTRAR_LSB = True
MAX_HEX_BYTES = 32


# ============================================================
# UTILIDADES
# ============================================================

def linha(char="=", tamanho=72):
    print(char * tamanho)


def titulo(texto):
    print()
    linha()
    print(texto)
    linha()


def hex_bytes(data: bytes, limite=None) -> str:
    if limite is not None and len(data) > limite:
        return (
            data[:limite].hex(" ")
            + f" ... ({len(data)} bytes no total)"
        )
    return data.hex(" ")


def bits2(valor: int) -> str:
    return format(valor & 0b11, "02b")


def comparar_bytes(original: bytes, payload: bytes):
    """Mostra diferenças entre carrier original e payload."""

    print(f"Carrier original: {len(original)} bytes")
    print(f"Payload:          {len(payload)} bytes")

    if len(original) != len(payload):
        print("[ERRO] Tamanhos diferentes.")
        return

    alterados = []

    for pos, (a, b) in enumerate(zip(original, payload)):
        if a != b:
            alterados.append((pos, a, b))

    print(f"Bytes alterados:   {len(alterados)}")

    if not alterados:
        print("[INFO] Nenhum byte foi alterado.")
        return

    print()
    print("Posição | Original | Payload | LSB orig. | LSB novo")
    print("-" * 56)

    for pos, original_byte, payload_byte in alterados:
        print(
            f"{pos:6d} | "
            f"0x{original_byte:02X}     | "
            f"0x{payload_byte:02X}   | "
            f"   {bits2(original_byte)}     | "
            f"   {bits2(payload_byte)}"
        )


# ============================================================
# DEBUG DO HEADER
# ============================================================

def debug_header(payload: bytes):
    titulo("HEADER")

    if len(payload) < HEADER_BYTES:
        print(
            f"[ERRO] Payload possui apenas {len(payload)} bytes; "
            f"HEADER_BYTES = {HEADER_BYTES}."
        )
        return None

    pos = 0

    magic, pos = ler_int(payload, pos, 16)
    total, pos = ler_int(payload, pos, 8)
    seq, pos = ler_int(payload, pos, 8)
    tam, pos = ler_int(payload, pos, 8)

    print(f"Magic esperado : 0x{MAGIC_HEADER:04X}")
    print(f"Magic recebido : 0x{magic:04X}")
    print(f"Magic válido   : {magic == MAGIC_HEADER}")
    print()

    print(f"Total          : {total}")
    print(f"Sequência      : {seq}")
    print(f"Tamanho        : {tam}")
    print(f"Bytes consumidos pelo header: {pos}")

    print()
    print("Validações:")

    ok = True

    if magic != MAGIC_HEADER:
        print("  [ERRO] MAGIC_HEADER inválido.")
        ok = False
    else:
        print("  [OK] MAGIC_HEADER.")

    if total == 0:
        print("  [ERRO] total == 0.")
        ok = False
    else:
        print("  [OK] total != 0.")

    if seq >= total:
        print("  [ERRO] seq >= total.")
        ok = False
    else:
        print("  [OK] seq < total.")

    if tam == 0:
        print("  [ERRO] tamanho == 0.")
        ok = False
    else:
        print("  [OK] tamanho != 0.")

    print()
    print("[OK] Header válido." if ok else "[ERRO] Header inválido.")

    return {
        "magic": magic,
        "total": total,
        "seq": seq,
        "tam": tam,
    }


# ============================================================
# PROCURA DOS MARCADORES
# ============================================================

def encontrar_marcadores(payload: bytes):
    titulo("PROCURA DO MAGIC_INICIO")

    encontrados = []

    if len(payload) < HEADER_BYTES + INICIO_BYTES:
        print("[ERRO] Payload pequeno demais.")
        return encontrados

    for p in range(
        HEADER_BYTES,
        len(payload) - INICIO_BYTES + 1
    ):
        valor, _ = ler_int(payload, p, 32)

        if valor == MAGIC_INICIO:
            encontrados.append(p)

    print(f"Magic procurado: 0x{MAGIC_INICIO:08X}")
    print(f"Ocorrências:     {len(encontrados)}")

    if not encontrados:
        print("[ERRO] Nenhum marcador encontrado.")
    else:
        for i, pos in enumerate(encontrados):
            print(f"  [{i}] posição {pos}")

    return encontrados


# ============================================================
# DEBUG DA MENSAGEM
# ============================================================

def debug_mensagem(payload: bytes, marcador: int, tamanho: int):
    titulo("REGIÃO DA MENSAGEM")

    msg_inicio = marcador + INICIO_BYTES
    msg_fim = msg_inicio + tamanho * 4

    print(f"Marcador:          {marcador}")
    print(f"INICIO_BYTES:      {INICIO_BYTES}")
    print(f"Início mensagem:   {msg_inicio}")
    print(f"Tamanho lógico:    {tamanho} bytes")
    print(f"Espaço carrier:    {tamanho * 4} bytes")
    print(f"Fim da região:     {msg_fim}")
    print(f"Tamanho carrier:   {len(payload)} bytes")

    if msg_fim > len(payload):
        print()
        print("[ERRO] Mensagem ultrapassa o final do carrier.")
        return None

    mensagem, fim_real = _ler_mensagem(payload, msg_inicio, tamanho)

    print()
    print(f"Fim calculado:     {msg_fim}")
    print(f"Fim da leitura:    {fim_real}")

    print()
    print(f"Mensagem recuperada: {mensagem!r}")
    print(f"Hex:                 {hex_bytes(mensagem)}")

    return mensagem


def _ler_mensagem(payload: bytes, pos: int, tamanho: int):
    resultado = bytearray()

    for _ in range(tamanho):
        valor, pos = ler_int(payload, pos, 8)
        resultado.append(valor)

    return bytes(resultado), pos


# ============================================================
# DEBUG DOS 2 LSBs
# ============================================================

def debug_lsb(payload: bytes, inicio: int, tamanho: int):
    titulo("MAPA DOS 2 LSBs")

    msg_inicio = inicio + INICIO_BYTES
    msg_fim = msg_inicio + tamanho * 4

    if msg_fim > len(payload):
        print("[ERRO] Região da mensagem inválida.")
        return

    print(
        "Posição | Byte | Binário   | 2 LSBs"
    )
    print("-" * 40)

    for pos in range(msg_inicio, msg_fim):
        byte = payload[pos]

        print(
            f"{pos:7d} | "
            f"0x{byte:02X} | "
            f"{byte:08b} | "
            f"  {byte & 0b11:02b}"
        )


# ============================================================
# DEBUG COMPLETO DE UM PAYLOAD
# ============================================================

def debug_payload(payload: bytes, numero=None):
    titulo(
        f"PAYLOAD {numero}"
        if numero is not None
        else "PAYLOAD"
    )

    print(f"Tamanho: {len(payload)} bytes")

    if MOSTRAR_HEX:
        print()
        print("Primeiros bytes:")
        print(hex_bytes(payload, MAX_HEX_BYTES))

    header = debug_header(payload)

    if header is None:
        return

    marcadores = encontrar_marcadores(payload)

    if not marcadores:
        return

    marcador = marcadores[0]

    mensagem = debug_mensagem(
        payload,
        marcador,
        header["tam"],
    )

    if MOSTRAR_LSB and mensagem is not None:
        debug_lsb(
            payload,
            marcador,
            header["tam"],
        )


# ============================================================
# TESTE DE UM FRAGMENTO
# ============================================================

def testar_fragmento(carrier: bytes, mensagem: bytes, seq: int, total: int):
    titulo(f"TESTE DO FRAGMENTO seq={seq}")

    print(f"Mensagem: {mensagem!r}")
    print(f"Tamanho:  {len(mensagem)}")
    print(f"Seq:      {seq}")
    print(f"Total:    {total}")

    payload = codificar(
        carrier,
        mensagem,
        seq,
        total,
    )

    print()
    print("Codificação concluída.")

    comparar_bytes(carrier, payload)

    resultado = decodificar(payload)

    print()
    print("Resultado da decodificação:")

    if resultado is None:
        print("[ERRO] Decodificação falhou.")
        return payload

    print(f"  seq:      {resultado['seq']}")
    print(f"  total:    {resultado['total']}")
    print(f"  mensagem: {resultado['mensagem']!r}")

    if resultado["mensagem"] == mensagem:
        print()
        print("[OK] Mensagem recuperada corretamente.")
    else:
        print()
        print("[ERRO] Mensagem recuperada é diferente.")

    return payload


# ============================================================
# TESTE COMPLETO
# ============================================================

def teste_completo():
    titulo("TESTE COMPLETO DO PROTOCOLO")

    carrier = (
        CARRIER
        if CARRIER is not None
        else os.urandom(CARRIER_TAMANHO)
    )

    print(f"Carrier:    {len(carrier)} bytes")
    print(f"Capacidade: {capacidade(carrier)} bytes/fragmento")
    print(f"Mensagem:   {MENSAGEM!r}")
    print(f"Tamanho:    {len(MENSAGEM)} bytes")

    cap = capacidade(carrier)

    if cap <= 0:
        print()
        print("[ERRO] Carrier não possui capacidade.")
        return

    if len(MENSAGEM) == 0:
        print()
        print("[ERRO] Mensagem vazia.")
        return

    print()
    print("Gerando fragmentos...")

    payloads = codificar_mensagem(
        MENSAGEM,
        carrier,
    )

    print(f"Fragmentos gerados: {len(payloads)}")

    # --------------------------------------------------------
    # Inspeção individual
    # --------------------------------------------------------

    for i, payload in enumerate(payloads):
        debug_payload(payload, i)

    # --------------------------------------------------------
    # Comparação dos payloads
    # --------------------------------------------------------

    titulo("COMPARAÇÃO DOS PAYLOADS")

    for i, payload in enumerate(payloads):
        print()
        print(f"Fragmento {i}:")
        comparar_bytes(carrier, payload)

    # --------------------------------------------------------
    # Decodificação individual
    # --------------------------------------------------------

    titulo("DECODIFICAÇÃO INDIVIDUAL")

    resultados = []

    for i, payload in enumerate(payloads):
        resultado = decodificar(payload)

        if resultado is None:
            print(f"[ERRO] Fragmento {i} não pôde ser decodificado.")
            continue

        resultados.append(resultado)

        print(
            f"[OK] fragmento={i} "
            f"seq={resultado['seq']} "
            f"total={resultado['total']} "
            f"tam={len(resultado['mensagem'])} "
            f"mensagem={resultado['mensagem']!r}"
        )

    # --------------------------------------------------------
    # Remontagem normal
    # --------------------------------------------------------

    titulo("REMONTAGEM NORMAL")

    recuperada = __import__("stego").remontar(payloads)

    if recuperada == MENSAGEM:
        print("[OK] Remontagem normal.")
        print(f"Mensagem: {recuperada!r}")
    else:
        print("[ERRO] Remontagem normal.")
        print(f"Esperado: {MENSAGEM!r}")
        print(f"Recebido: {recuperada!r}")

    # --------------------------------------------------------
    # Remontagem fora de ordem
    # --------------------------------------------------------

    titulo("REMONTAGEM FORA DE ORDEM")

    invertidos = list(reversed(payloads))

    recuperada = __import__("stego").remontar(invertidos)

    if recuperada == MENSAGEM:
        print("[OK] Remontagem fora de ordem.")
        print(f"Mensagem: {recuperada!r}")
    else:
        print("[ERRO] Remontagem fora de ordem.")
        print(f"Esperado: {MENSAGEM!r}")
        print(f"Recebido: {recuperada!r}")

    # --------------------------------------------------------
    # Resumo
    # --------------------------------------------------------

    titulo("RESUMO")

    print(f"Carrier              : {len(carrier)} bytes")
    print(f"Capacidade/fragmento : {cap} bytes")
    print(f"Mensagem             : {len(MENSAGEM)} bytes")
    print(f"Fragmentos           : {len(payloads)}")
    print()

    if recuperada == MENSAGEM:
        print("[OK] PROTOCOLO FUNCIONANDO.")
    else:
        print("[ERRO] PROTOCOLO COM FALHA.")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    teste_completo()
