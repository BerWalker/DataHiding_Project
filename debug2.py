"""
debug.py — Inspeção detalhada do protocolo de esteganografia.

Uso:
    python debug.py
    python debug.py "outra mensagem"

O arquivo stego.py permanece sem código de debug.
"""

import sys

import stego

from stego import (
    MAGIC_HEADER,
    MAGIC_INICIO,
    HEADER_BYTES,
    INICIO_BYTES,
    capacidade,
    codificar_mensagem,
    codificar,
    decodificar,
    ler_bits,
    ler_bytes,
)


# ============================================================
# CONFIGURAÇÃO VISUAL
# ============================================================

W = 90

RESET = "\033[0m"
BOLD = "\033[1m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
GRAY = "\033[90m"
WHITE = "\033[97m"


def cor(texto, codigo):
    return f"{codigo}{texto}{RESET}"


def secao(titulo):
    print()
    print(cor("═" * W, CYAN))
    print(cor(f"  {titulo}", BOLD + CYAN))
    print(cor("═" * W, CYAN))


def subseção(titulo):
    print()
    print(cor(f"--- {titulo} ---", BLUE))


def ok(texto):
    print(f"  {cor('✓', GREEN)} {texto}")


def erro(texto):
    print(f"  {cor('✗', RED)} {texto}")


def aviso(texto):
    print(f"  {cor('!', YELLOW)} {texto}")


def info(texto):
    print(f"     {texto}")


# ============================================================
# FORMATAÇÃO
# ============================================================

def bits8(valor):
    return f"{valor:08b}"


def bits2(valor):
    return f"{valor:02b}"


def hex_bytes(dados):
    return " ".join(f"{b:02X}" for b in dados)


def texto_seguro(dados):
    return "".join(
        chr(b) if 32 <= b <= 126 else "."
        for b in dados
    )


# ============================================================
# MAPA DO PAYLOAD
# ============================================================

def mapa_payload(payload, inicio, tamanho):
    """
    Identifica a função de cada byte do carrier.

    H = Header
    M = Marcador
    D = Dados
    . = Não utilizado
    """

    mapa = ["."] * len(payload)

    # Header
    for i in range(
        min(HEADER_BYTES, len(payload))
    ):
        mapa[i] = "H"

    # Marcador
    if inicio is not None:
        for i in range(
            inicio,
            min(inicio + INICIO_BYTES, len(payload))
        ):
            mapa[i] = "M"

        # Mensagem
        msg_inicio = inicio + INICIO_BYTES
        msg_fim = msg_inicio + tamanho * 4

        for i in range(
            msg_inicio,
            min(msg_fim, len(payload))
        ):
            mapa[i] = "D"

    return mapa


def imprimir_mapa(payload, inicio, tamanho):
    mapa = mapa_payload(
        payload,
        inicio,
        tamanho
    )

    cols = 16

    print()

    print("      ", end="")

    for i in range(cols):
        print(f"{i:02X} ", end="")

    print()

    print("     " + "─" * (cols * 3))

    for linha in range(
        0,
        len(payload),
        cols
    ):
        print(f"  {linha:02X} ", end="")

        for simbolo in mapa[linha:linha + cols]:

            if simbolo == "H":
                c = BLUE
            elif simbolo == "M":
                c = GREEN
            elif simbolo == "D":
                c = YELLOW
            else:
                c = GRAY

            print(
                cor(simbolo, c),
                end="  "
            )

        print()

    print()

    print(
        f"     {cor('H', BLUE)} = Header"
    )

    print(
        f"     {cor('M', GREEN)} = Marcador"
    )

    print(
        f"     {cor('D', YELLOW)} = Dados"
    )

    print(
        f"     {cor('.', GRAY)} = Não utilizado"
    )


# ============================================================
# INFORMAÇÕES GERAIS
# ============================================================

def mostrar_configuracao(mensagem, carrier):
    secao("CONFIGURAÇÃO")

    info(
        f"MAGIC_HEADER : "
        f"0x{MAGIC_HEADER:04X}"
    )

    info(
        f"MAGIC_INICIO : "
        f"0x{MAGIC_INICIO:04X}"
    )

    info(
        f"HEADER_BYTES : "
        f"{HEADER_BYTES}"
    )

    info(
        f"INICIO_BYTES : "
        f"{INICIO_BYTES}"
    )

    info(
        f"Carrier      : "
        f"{len(carrier)} bytes"
    )

    info(
        f"Mensagem     : "
        f"{len(mensagem)} bytes"
    )

    info(
        f"Capacidade   : "
        f"{capacidade(carrier)} bytes/fragmento"
    )

    print()

    print(
        f"Mensagem: "
        f"{cor(repr(mensagem), MAGENTA)}"
    )

    print(
        f"Hex:      "
        f"{cor(hex_bytes(mensagem), CYAN)}"
    )


# ============================================================
# FRAGMENTAÇÃO
# ============================================================

def mostrar_fragmentacao(mensagem, carrier):
    secao("FRAGMENTAÇÃO")

    cap = capacidade(carrier)

    if cap <= 0:
        raise ValueError(
            "Carrier não possui capacidade para mensagem."
        )

    fragmentos = [
        mensagem[i:i + cap]
        for i in range(
            0,
            len(mensagem),
            cap
        )
    ]

    info(
        f"Capacidade por fragmento: "
        f"{cap} bytes"
    )

    info(
        f"Mensagem total: "
        f"{len(mensagem)} bytes"
    )

    info(
        f"Quantidade de fragmentos: "
        f"{len(fragmentos)}"
    )

    print()

    for i, fragmento in enumerate(fragmentos):

        print(
            f"  {cor(f'[{i}]', CYAN)} "
            f"{len(fragmento):3d} bytes  "
            f"{repr(fragmento)}"
        )

        print(
            f"       HEX: "
            f"{hex_bytes(fragmento)}"
        )

    return fragmentos


# ============================================================
# BYTES ALTERADOS
# ============================================================

def mostrar_bytes_alterados(carrier_original, payload):
    secao("BYTES ALTERADOS")

    alterados = []

    for i, (original, novo) in enumerate(
        zip(carrier_original, payload)
    ):
        if original != novo:
            alterados.append(
                (i, original, novo)
            )

    info(
        f"Carrier original : "
        f"{len(carrier_original)} bytes"
    )

    info(
        f"Payload          : "
        f"{len(payload)} bytes"
    )

    info(
        f"Bytes alterados  : "
        f"{len(alterados)}"
    )

    info(
        f"Bytes intactos   : "
        f"{len(payload) - len(alterados)}"
    )

    if not alterados:
        aviso("Nenhum byte foi alterado.")
        return

    print()

    print(
        "  POS    ORIGINAL       PAYLOAD       XOR       "
        "LSB original   LSB novo"
    )

    print(
        "  " + "─" * 78
    )

    for pos, original, novo in alterados:

        xor = original ^ novo

        print(
            f"  {pos:04d}   "
            f"0x{original:02X} "
            f"{bits8(original)}   "
            f"0x{novo:02X} "
            f"{bits8(novo)}   "
            f"0x{xor:02X}   "
            f"{bits2(original & 0b11)}"
            f"            "
            f"{cor(bits2(novo & 0b11), YELLOW)}"
        )


# ============================================================
# PAYLOAD COMPLETO
# ============================================================

def mostrar_payload(payload, carrier_original=None):
    secao(
        f"PAYLOAD COMPLETO ({len(payload)} bytes)"
    )

    print()

    print(
        cor(
            "HEX:",
            BOLD + CYAN
        )
    )

    print(
        hex_bytes(payload)
    )

    print()

    print(
        cor(
            "TABELA:",
            BOLD + CYAN
        )
    )

    print()

    print(
        "  POS   HEX   BINÁRIO     ASCII    LSB"
    )

    print(
        "  " + "─" * 43
    )

    for i, byte in enumerate(payload):

        ascii_char = (
            chr(byte)
            if 32 <= byte <= 126
            else "."
        )

        lsb = byte & 0b11

        alterado = (
            carrier_original is not None
            and i < len(carrier_original)
            and carrier_original[i] != byte
        )

        if alterado:
            c = YELLOW
        else:
            c = GRAY

        print(
            cor(
                f"  {i:04d}  "
                f"{byte:02X}    "
                f"{byte:08b}      "
                f"{ascii_char!r}       "
                f"{lsb:02b}",
                c
            )
        )


# ============================================================
# HEADER
# ============================================================

def inspecionar_header(payload):
    secao("HEADER")

    pos = 0

    magic, pos = ler_bits(
        payload,
        pos,
        16
    )

    total, pos = ler_bits(
        payload,
        pos,
        8
    )

    seq, pos = ler_bits(
        payload,
        pos,
        8
    )

    tamanho, pos = ler_bits(
        payload,
        pos,
        8
    )

    print()

    info(
        f"Magic:   "
        f"0x{magic:04X}  "
        f"bits={bits8(magic >> 8)}"
        f"{bits8(magic & 0xFF)}"
    )

    info(
        f"Total:   {total}"
    )

    info(
        f"Seq:     {seq}"
    )

    info(
        f"Tamanho: {tamanho} bytes"
    )

    info(
        f"Próxima posição: {pos}"
    )

    print()

    if magic == MAGIC_HEADER:
        ok(
            f"MAGIC_HEADER correto "
            f"(0x{MAGIC_HEADER:04X})"
        )
    else:
        erro(
            f"MAGIC_HEADER inválido. "
            f"Esperado 0x{MAGIC_HEADER:04X}"
        )

    if total > 0:
        ok(f"Total válido: {total}")
    else:
        erro("Total inválido")

    if seq < total:
        ok(f"Sequência válida: {seq}")
    else:
        erro(
            f"Sequência inválida: "
            f"{seq} >= {total}"
        )

    if tamanho > 0:
        ok(f"Tamanho válido: {tamanho}")
    else:
        erro("Tamanho inválido")

    return magic, total, seq, tamanho


# ============================================================
# MARCADOR
# ============================================================

def inspecionar_marcador(payload):
    secao("MARCADOR DE INÍCIO")

    inicio = None
    tentativas = 0

    for p in range(
        HEADER_BYTES,
        len(payload) - INICIO_BYTES + 1
    ):

        valor, _ = ler_bits(
            payload,
            p,
            16
        )

        tentativas += 1

        if valor == MAGIC_INICIO:
            inicio = p
            break

    info(
        f"Início da busca: "
        f"{HEADER_BYTES}"
    )

    info(
        f"Posições verificadas: "
        f"{tentativas}"
    )

    if inicio is None:

        erro(
            "MAGIC_INICIO não encontrado."
        )

        return None

    ok(
        f"MAGIC_INICIO encontrado "
        f"na posição {inicio}"
    )

    info(
        f"Valor: "
        f"0x{MAGIC_INICIO:04X}"
    )

    info(
        f"Carrier usado: "
        f"{inicio} → "
        f"{inicio + INICIO_BYTES - 1}"
    )

    info(
        f"Tamanho: "
        f"{INICIO_BYTES} bytes"
    )

    return inicio


# ============================================================
# MENSAGEM
# ============================================================

def inspecionar_mensagem(
    payload,
    inicio,
    tamanho
):
    secao("DADOS DA MENSAGEM")

    if inicio is None:
        erro(
            "Não é possível localizar a mensagem."
        )
        return None

    msg_inicio = (
        inicio + INICIO_BYTES
    )

    msg_fim = (
        msg_inicio +
        tamanho * 4 -
        1
    )

    info(
        f"Início no carrier: "
        f"{msg_inicio}"
    )

    info(
        f"Fim no carrier: "
        f"{msg_fim}"
    )

    info(
        f"Bytes do carrier usados: "
        f"{tamanho * 4}"
    )

    info(
        f"Bytes reais da mensagem: "
        f"{tamanho}"
    )

    info(
        "Relação: 1 byte de mensagem = "
        "4 bytes de carrier"
    )

    if msg_fim >= len(payload):
        erro(
            "Mensagem ultrapassa o payload."
        )
        return None

    mensagem, _ = ler_bytes(
        payload,
        msg_inicio,
        tamanho
    )

    print()

    info(
        f"Mensagem recuperada: "
        f"{repr(mensagem)}"
    )

    info(
        f"HEX: "
        f"{hex_bytes(mensagem)}"
    )

    info(
        f"ASCII: "
        f"{texto_seguro(mensagem)}"
    )

    return mensagem


# ============================================================
# LSBs
# ============================================================

def inspecionar_lsbs(
    payload,
    inicio,
    tamanho
):
    secao("LSBs DO CARRIER")

    mapa = mapa_payload(
        payload,
        inicio,
        tamanho
    )

    print()

    print(
        "  POS    BYTE       BINÁRIO       LSB    FUNÇÃO"
    )

    print(
        "  " + "─" * 58
    )

    for i, byte in enumerate(payload):

        funcao = mapa[i]

        if funcao == "H":
            c = BLUE
            nome = "HEADER"
        elif funcao == "M":
            c = GREEN
            nome = "MARCADOR"
        elif funcao == "D":
            c = YELLOW
            nome = "DADO"
        else:
            c = GRAY
            nome = "LIVRE"

        print(
            f"  {i:04d}   "
            f"0x{byte:02X}     "
            f"{byte:08b}      "
            f"{cor(bits2(byte & 0b11), c)}    "
            f"{cor(nome, c)}"
        )


# ============================================================
# COMPARAÇÃO DE MENSAGEM
# ============================================================

def comparar_mensagem(
    original,
    recuperada
):
    secao("COMPARAÇÃO FINAL")

    if recuperada == original:

        ok("A mensagem foi recuperada corretamente.")

        print()
        info(
            f"Original : {original!r}"
        )

        info(
            f"Recebida : {recuperada!r}"
        )

        return True

    erro(
        "A mensagem recuperada é diferente."
    )

    print()

    info(
        f"Original : {original!r}"
    )

    info(
        f"Recebida : {recuperada!r}"
    )

    print()

    tamanho = max(
        len(original),
        len(recuperada or b"")
    )

    for i in range(tamanho):

        a = (
            original[i]
            if i < len(original)
            else None
        )

        b = (
            recuperada[i]
            if recuperada is not None
            and i < len(recuperada)
            else None
        )

        if a != b:

            print(
                f"  posição {i}: "
                f"{cor(str(a), RED)} → "
                f"{cor(str(b), RED)}"
            )

    return False


# ============================================================
# INSPEÇÃO DE UM PAYLOAD
# ============================================================

def inspecionar_payload(
    payload,
    carrier_original,
    indice
):
    print()

    print(
        cor(
            "╔" + "═" * (W - 2) + "╗",
            MAGENTA
        )
    )

    titulo = (
        f" PAYLOAD {indice} "
        f"({len(payload)} bytes) "
    )

    print(
        cor(
            "║" +
            titulo.center(W - 2) +
            "║",
            MAGENTA + BOLD
        )
    )

    print(
        cor(
            "╚" + "═" * (W - 2) + "╝",
            MAGENTA
        )
    )

    # Header
    (
        magic,
        total,
        seq,
        tamanho
    ) = inspecionar_header(payload)

    if magic != MAGIC_HEADER:
        erro(
            "Payload inválido por causa do MAGIC_HEADER."
        )
        return None

    # Marcador
    inicio = inspecionar_marcador(
        payload
    )

    # Mensagem
    mensagem = inspecionar_mensagem(
        payload,
        inicio,
        tamanho
    )

    # Mapa
    secao("MAPA DO CARRIER")

    if inicio is not None:
        imprimir_mapa(
            payload,
            inicio,
            tamanho
        )

    # LSBs
    inspecionar_lsbs(
        payload,
        inicio,
        tamanho
    )

    # Bytes alterados
    mostrar_bytes_alterados(
        carrier_original,
        payload
    )

    # Payload
    mostrar_payload(
        payload,
        carrier_original
    )

    # Resultado da API
    secao("DECODIFICAÇÃO VIA STEGO.PY")

    resultado = decodificar(payload)

    if resultado is None:

        erro(
            "stego.decodificar() retornou None."
        )

        return None

    ok("Payload aceito pelo protocolo.")

    info(
        f"seq      = {resultado['seq']}"
    )

    info(
        f"total    = {resultado['total']}"
    )

    info(
        f"mensagem = {resultado['mensagem']!r}"
    )

    return resultado


# ============================================================
# REMONTAGEM
# ============================================================

def testar_remontagem(
    payloads,
    mensagem_original
):
    secao("REMONTAGEM FORA DE ORDEM")

    indices = list(
        range(len(payloads))
    )

    indices.reverse()

    info(
        f"Ordem original: "
        f"{list(range(len(payloads)))}"
    )

    info(
        f"Ordem testada:  "
        f"{indices}"
    )

    print()

    fragmentos = {}
    total = None

    for indice in indices:

        resultado = decodificar(
            payloads[indice]
        )

        if resultado is None:

            erro(
                f"Payload {indice}: "
                f"falha na decodificação"
            )

            continue

        seq = resultado["seq"]

        if total is None:
            total = resultado["total"]

        fragmentos[seq] = resultado[
            "mensagem"
        ]

        info(
            f"Payload {indice} → "
            f"seq={seq} "
            f"({len(fragmentos)}/{total})"
        )

    print()

    if total is None:
        erro("Nenhum fragmento válido.")
        return None

    if len(fragmentos) != total:

        erro(
            f"Remontagem incompleta: "
            f"{len(fragmentos)}/{total}"
        )

        return None

    recuperada = b"".join(
        fragmentos[i]
        for i in range(total)
    )

    ok(
        "Todos os fragmentos foram encontrados."
    )

    comparar_mensagem(
        mensagem_original,
        recuperada
    )

    return recuperada


# ============================================================
# TESTE DE CODIFICAÇÃO INDIVIDUAL
# ============================================================

def testar_codificacao_individual(
    carrier
):
    secao("TESTE DE CODIFICAÇÃO INDIVIDUAL")

    mensagem = b"ABC"

    info(
        f"Mensagem de teste: "
        f"{mensagem!r}"
    )

    payload = codificar(
        carrier,
        mensagem,
        seq=0,
        total=1
    )

    ok(
        f"Payload criado: "
        f"{len(payload)} bytes"
    )

    resultado = decodificar(
        payload
    )

    if resultado is None:

        erro(
            "Falha ao decodificar payload."
        )

        return

    if resultado["mensagem"] == mensagem:

        ok(
            "Codificação individual "
            "funciona corretamente."
        )

    else:

        erro(
            "Mensagem individual "
            "não foi recuperada."
        )


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # Mensagem
    # --------------------------------------------------------

    if len(sys.argv) > 1:
        mensagem = sys.argv[1].encode()
    else:
        mensagem = (
            b"Hello, World!"
        )

    # Usa o carrier definido em stego.py
    if stego.CARRIER is not None:
        carrier = stego.CARRIER
    else:
        carrier = os.urandom(
            stego.CARRIER_TAMANHO
        )

    print()
    print(
        cor(
            "╔" + "═" * (W - 2) + "╗",
            CYAN
        )
    )

    print(
        cor(
            "║" +
            " DEBUG DO PROTOCOLO DE ESTEGANOGRAFIA ".center(W - 2) +
            "║",
            CYAN + BOLD
        )
    )

    print(
        cor(
            "╚" + "═" * (W - 2) + "╝",
            CYAN
        )
    )

    # --------------------------------------------------------
    # Configuração
    # --------------------------------------------------------

    mostrar_configuracao(
        mensagem,
        carrier
    )

    # --------------------------------------------------------
    # Teste básico
    # --------------------------------------------------------

    testar_codificacao_individual(
        carrier
    )

    # --------------------------------------------------------
    # Fragmentação
    # --------------------------------------------------------

    mostrar_fragmentacao(
        mensagem,
        carrier
    )

    # --------------------------------------------------------
    # Codificação
    # --------------------------------------------------------

    secao("CODIFICAÇÃO DA MENSAGEM")

    payloads = codificar_mensagem(
        mensagem,
        carrier
    )

    ok(
        f"{len(payloads)} payload(s) gerado(s)"
    )

    # --------------------------------------------------------
    # Inspeciona cada payload
    # --------------------------------------------------------

    for seq, payload in enumerate(
        payloads
    ):

        inspecionar_payload(
            payload,
            carrier,
            seq
        )

    # --------------------------------------------------------
    # Remontagem
    # --------------------------------------------------------

    testar_remontagem(
        payloads,
        mensagem
    )

    # --------------------------------------------------------
    # Final
    # --------------------------------------------------------

    print()

    print(
        cor(
            "═" * W,
            GREEN
        )
    )

    print(
        cor(
            "  DEBUG FINALIZADO",
            GREEN + BOLD
        )
    )

    print(
        cor(
            "═" * W,
            GREEN
        )
    )


if __name__ == "__main__":
    main()
