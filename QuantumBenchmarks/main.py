from pqcrypto.kem.kyber import (
    Kyber512_KEYPAIR, Kyber512_ENCAPSULATE, Kyber512_DECAPSULATE,
    Kyber768_KEYPAIR, Kyber768_ENCAPSULATE, Kyber768_DECAPSULATE,
    Kyber1024_KEYPAIR, Kyber1024_ENCAPSULATE, Kyber1024_DECAPSULATE
)
from pqcrypto.sign.dilithium import (
    Dilithium2_KEYPAIR, Dilithium2_SIGN, Dilithium2_VERIFY,
    Dilithium3_KEYPAIR, Dilithium3_SIGN, Dilithium3_VERIFY,
    Dilithium5_KEYPAIR, Dilithium5_SIGN, Dilithium5_VERIFY
)
from pqcrypto.sign.sphincs import (
    SphincsHaraka128fSimple_KEYPAIR, SphincsHaraka128fSimple_SIGN, SphincsHaraka128fSimple_VERIFY
)
import time
import numpy as np


def benchmark_kyber():
    """Benchmark do Kyber KEM em diferentes níveis de segurança"""
    resultados = {}

    for nivel, (keygen, encaps, decaps) in {
        "Kyber-512": (Kyber512_KEYPAIR, Kyber512_ENCAPSULATE, Kyber512_DECAPSULATE),
        "Kyber-768": (Kyber768_KEYPAIR, Kyber768_ENCAPSULATE, Kyber768_DECAPSULATE),
        "Kyber-1024": (Kyber1024_KEYPAIR, Kyber1024_ENCAPSULATE, Kyber1024_DECAPSULATE)
    }.items():
        # Medir tempo de geração de chaves
        inicio = time.time()
        for _ in range(100):
            public_key, secret_key = keygen()
        tempo_keygen = (time.time() - inicio) / 100

        # Medir tempo de encapsulamento
        inicio = time.time()
        for _ in range(100):
            ciphertext, shared_secret = encaps(public_key)
        tempo_encaps = (time.time() - inicio) / 100

        # Medir tempo de decapsulamento
        inicio = time.time()
        for _ in range(100):
            decrypted_shared_secret = decaps(secret_key, ciphertext)
        tempo_decaps = (time.time() - inicio) / 100

        # Armazenar tamanhos
        tamanho_pk = len(public_key)
        tamanho_sk = len(secret_key)
        tamanho_ct = len(ciphertext)

        resultados[nivel] = {
            "tempo_keygen": tempo_keygen,
            "tempo_encaps": tempo_encaps,
            "tempo_decaps": tempo_decaps,
            "tamanho_pk": tamanho_pk,
            "tamanho_sk": tamanho_sk,
            "tamanho_ct": tamanho_ct
        }

    return resultados


def benchmark_dilithium():
    """Benchmark do Dilithium em diferentes níveis de segurança"""
    resultados = {}

    for nivel, (keygen, sign, verify) in {
        "Dilithium2": (Dilithium2_KEYPAIR, Dilithium2_SIGN, Dilithium2_VERIFY),
        "Dilithium3": (Dilithium3_KEYPAIR, Dilithium3_SIGN, Dilithium3_VERIFY),
        "Dilithium5": (Dilithium5_KEYPAIR, Dilithium5_SIGN, Dilithium5_VERIFY)
    }.items():
        # Medir tempo de geração de chaves
        inicio = time.time()
        for _ in range(100):
            public_key, secret_key = keygen()
        tempo_keygen = (time.time() - inicio) / 100

        # Mensagem de teste
        mensagem = b"Teste de assinatura digital pos-quantica com Dilithium"

        # Medir tempo de assinatura
        inicio = time.time()
        for _ in range(100):
            signature = sign(secret_key, mensagem)
        tempo_sign = (time.time() - inicio) / 100

        # Medir tempo de verificação
        inicio = time.time()
        for _ in range(100):
            result = verify(public_key, mensagem, signature)
        tempo_verify = (time.time() - inicio) / 100

        # Armazenar tamanhos
        tamanho_pk = len(public_key)
        tamanho_sk = len(secret_key)
        tamanho_sig = len(signature)

        resultados[nivel] = {
            "tempo_keygen": tempo_keygen,
            "tempo_sign": tempo_sign,
            "tempo_verify": tempo_verify,
            "tamanho_pk": tamanho_pk,
            "tamanho_sk": tamanho_sk,
            "tamanho_sig": tamanho_sig
        }

    return resultados


def benchmark_sphincs():
    """Benchmark do SPHINCS+"""
    resultados = {}

    keygen = SphincsHaraka128fSimple_KEYPAIR
    sign = SphincsHaraka128fSimple_SIGN
    verify = SphincsHaraka128fSimple_VERIFY

    # Medir tempo de geração de chaves
    inicio = time.time()
    for _ in range(10):  # SPHINCS+ é mais lento, então fazemos menos iterações
        public_key, secret_key = keygen()
    tempo_keygen = (time.time() - inicio) / 10

    # Mensagem de teste
    mensagem = b"Teste de assinatura digital pos-quantica com SPHINCS+"

    # Medir tempo de assinatura
    inicio = time.time()
    for _ in range(10):
        signature = sign(secret_key, mensagem)
    tempo_sign = (time.time() - inicio) / 10

    # Medir tempo de verificação
    inicio = time.time()
    for _ in range(10):
        result = verify(public_key, mensagem, signature)
    tempo_verify = (time.time() - inicio) / 10

    # Armazenar tamanhos
    tamanho_pk = len(public_key)
    tamanho_sk = len(secret_key)
    tamanho_sig = len(signature)

    resultados["SPHINCS+"] = {
        "tempo_keygen": tempo_keygen,
        "tempo_sign": tempo_sign,
        "tempo_verify": tempo_verify,
        "tamanho_pk": tamanho_pk,
        "tamanho_sk": tamanho_sk,
        "tamanho_sig": tamanho_sig
    }

    return resultados

    # Executar benchmarks
    resultados_kyber = benchmark_kyber()
    resultados_dilithium = benchmark_dilithium()
    resultados_sphincs = benchmark_sphincs()

    # Imprimir resultados
    print("Resultados do benchmark Kyber (KEM):")
    for nivel, resultado in resultados_kyber.items():
        print(f"{nivel}:")
        print(f"  Tempo médio de geração de chaves: {resultado['tempo_keygen'] * 1000:.2f} ms")
        print(f"  Tempo médio de encapsulamento: {resultado['tempo_encaps'] * 1000:.2f} ms")
        print(f"  Tempo médio de decapsulamento: {resultado['tempo_decaps'] * 1000:.2f} ms")
        print(f"  Tamanho da chave pública: {resultado['tamanho_pk']} bytes")
        print(f"  Tamanho da chave privada: {resultado['tamanho_sk']} bytes")
        print(f"  Tamanho do criptograma: {resultado['tamanho_ct']} bytes")

    print("\nResultados do benchmark Dilithium (Assinatura):")
    for nivel, resultado in resultados_dilithium.items():
        print(f"{nivel}:")
        print(f"  Tempo médio de geração de chaves: {resultado['tempo_keygen'] * 1000:.2f} ms")
        print(f"  Tempo médio de assinatura: {resultado['tempo_sign'] * 1000:.2f} ms")
        print(f"  Tempo médio de verificação: {resultado['tempo_verify'] * 1000:.2f} ms")
        print(f"  Tamanho da chave pública: {resultado['tamanho_pk']} bytes")
        print(f"  Tamanho da chave privada: {resultado['tamanho_sk']} bytes")
        print(f"  Tamanho da assinatura: {resultado['tamanho_sig']} bytes")

    print("\nResultados do benchmark SPHINCS+ (Assinatura):")
    for nivel, resultado in resultados_sphincs.items():
        print(f"{nivel}:")
        print(f"  Tempo médio de geração de chaves: {resultado['tempo_keygen'] * 1000:.2f} ms")
        print(f"  Tempo médio de assinatura: {resultado['tempo_sign'] * 1000:.2f} ms")
        print(f"  Tempo médio de verificação: {resultado['tempo_verify'] * 1000:.2f}")
        print("\nResultados do benchmark SPHINCS+ (Assinatura):")

    # Função para criar gráfico comparativo
    def criar_grafico_comparativo():
        # Cria gráficos comparativos dos resultados
        import matplotlib.pyplot as plt
        import numpy as np

        # Preparar dados para gráfico de tempos (ms)
        algoritmos = []
        tempos_keygen = []
        tempos_operacao1 = []  # encaps ou sign
        tempos_operacao2 = []  # decaps ou verify

        # Adicionar dados do Kyber
        for nivel, resultado in resultados_kyber.items():
            algoritmos.append(nivel)
            tempos_keygen.append(resultado['tempo_keygen'] * 1000)
            tempos_operacao1.append(resultado['tempo_encaps'] * 1000)
            tempos_operacao2.append(resultado['tempo_decaps'] * 1000)

        # Adicionar dados do Dilithium
        for nivel, resultado in resultados_dilithium.items():
            algoritmos.append(nivel)
            tempos_keygen.append(resultado['tempo_keygen'] * 1000)
            tempos_operacao1.append(resultado['tempo_sign'] * 1000)
            tempos_operacao2.append(resultado['tempo_verify'] * 1000)

        # Adicionar dados do SPHINCS+
        for nivel, resultado in resultados_sphincs.items():
            algoritmos.append(nivel)
            tempos_keygen.append(resultado['tempo_keygen'] * 1000)
            tempos_operacao1.append(resultado['tempo_sign'] * 1000)
            tempos_operacao2.append(resultado['tempo_verify'] * 1000)

        # Criar gráfico de barras para tempos
        x = np.arange(len(algoritmos))
        largura = 0.25

        fig, ax = plt.subplots(figsize=(12, 8))
        rects1 = ax.bar(x - largura, tempos_keygen, largura, label='Geração de Chaves')
        rects2 = ax.bar(x, tempos_operacao1, largura, label='Encaps/Sign')
        rects3 = ax.bar(x + largura, tempos_operacao2, largura, label='Decaps/Verify')

        ax.set_ylabel('Tempo (ms)')
        ax.set_title('Comparação de Desempenho de Algoritmos Pós-Quânticos')
        ax.set_xticks(x)
        ax.set_xticklabels(algoritmos)
        ax.legend()

        # Função para adicionar rótulos às barras
        def autolabel(rects):
            for rect in rects:
                height = rect.get_height()
                ax.annotate(f'{height:.1f}',
                            xy=(rect.get_x() + rect.get_width() / 2, height),
                            xytext=(0, 3),
                            textcoords="offset points",
                            ha='center', va='bottom', rotation=90)

        autolabel(rects1)
        autolabel(rects2)
        autolabel(rects3)

        fig.tight_layout()
        plt.savefig('benchmark_algoritmos_pq.png', dpi=300)
        plt.close()

        # Criar gráfico de tamanhos de chave e assinatura/criptograma
        tamanhos_pk = []
        tamanhos_sk = []
        tamanhos_output = []  # criptograma ou assinatura

        # Adicionar dados do Kyber
        for nivel, resultado in resultados_kyber.items():
            tamanhos_pk.append(resultado['tamanho_pk'])
            tamanhos_sk.append(resultado['tamanho_sk'])
            tamanhos_output.append(resultado['tamanho_ct'])

        # Adicionar dados do Dilithium
        for nivel, resultado in resultados_dilithium.items():
            tamanhos_pk.append(resultado['tamanho_pk'])
            tamanhos_sk.append(resultado['tamanho_sk'])
            tamanhos_output.append(resultado['tamanho_sig'])

        # Adicionar dados do SPHINCS+
        for nivel, resultado in resultados_sphincs.items():
            tamanhos_pk.append(resultado['tamanho_pk'])
            tamanhos_sk.append(resultado['tamanho_sk'])
            tamanhos_output.append(resultado['tamanho_sig'])

        # Criar gráfico de barras para tamanhos
        fig, ax = plt.subplots(figsize=(12, 8))
        rects1 = ax.bar(x - largura, tamanhos_pk, largura, label='Chave Pública')
        rects2 = ax.bar(x, tamanhos_sk, largura, label='Chave Privada')
        rects3 = ax.bar(x + largura, tamanhos_output, largura, label='Criptograma/Assinatura')

        ax.set_ylabel('Tamanho (bytes)')
        ax.set_title('Comparação de Tamanhos de Algoritmos Pós-Quânticos')
        ax.set_xticks(x)
        ax.set_xticklabels(algoritmos)
        ax.legend()

        autolabel(rects1)
        autolabel(rects2)
        autolabel(rects3)

        ax.set_yscale('log')  # Escala logarítmica devido às grandes diferenças
        fig.tight_layout()
        plt.savefig('tamanhos_algoritmos_pq.png', dpi=300)
        plt.close()

    # Executar a função para criar os gráficos
    try:
        criar_grafico_comparativo()
        print("Gráficos comparativos gerados com sucesso.")
    except ImportError:
        print("Não foi possível gerar gráficos. Matplotlib não disponível.")

    # Comparação com RSA e ECC (valores de referência)
    print("\nComparação com algoritmos clássicos (valores de referência):")
    print("RSA-2048:")
    print("  Tempo médio de geração de chaves: ~240 ms")
    print("  Tempo médio de encriptação: ~0.3 ms")
    print("  Tempo médio de decriptação: ~5 ms")
    print("  Tamanho da chave pública: 256 bytes")
    print("  Tamanho da chave privada: 1218 bytes")
    print("  Tamanho da assinatura: 256 bytes")

    print("\nECDSA P-256:")
    print("  Tempo médio de geração de chaves: ~0.2 ms")
    print("  Tempo médio de assinatura: ~0.4 ms")
    print("  Tempo médio de verificação: ~1.0 ms")
    print("  Tamanho da chave pública: 64 bytes")
    print("  Tamanho da chave privada: 32 bytes")
    print("  Tamanho da assinatura: 64 bytes")


# Salvar resultados em arquivo CSV para análise posterior
import csv

with open('resultados_benchmarks.csv', 'w', newline='') as arquivo_csv:
    writer = csv.writer(arquivo_csv)

    # Escrever cabeçalho
    writer.writerow(['Algoritmo', 'Tipo', 'Tempo Geração Chaves (ms)', 'Tempo Operação 1 (ms)',
                     'Tempo Operação 2 (ms)', 'Tamanho PK (bytes)', 'Tamanho SK (bytes)',
                     'Tamanho Saída (bytes)'])

    # Escrever dados Kyber
    for nivel, resultado in resultados_kyber.items():
        writer.writerow([
            nivel, 'KEM',
            resultado['tempo_keygen'] * 1000,
            resultado['tempo_encaps'] * 1000,
            resultado['tempo_decaps'] * 1000,
            resultado['tamanho_pk'],
            resultado['tamanho_sk'],
            resultado['tamanho_ct']
        ])

    # Escrever dados Dilithium
    for nivel, resultado in resultados_dilithium.items():
        writer.writerow([
            nivel, 'Assinatura',
            resultado['tempo_keygen'] * 1000,
            resultado['tempo_sign'] * 1000,
            resultado['tempo_verify'] * 1000,
            resultado['tamanho_pk'],
            resultado['tamanho_sk'],
            resultado['tamanho_sig']
        ])

    # Escrever dados SPHINCS+
    for nivel, resultado in resultados_sphincs.items():
        writer.writerow([
            nivel, 'Assinatura',
            resultado['tempo_keygen'] * 1000,
            resultado['tempo_sign'] * 1000,
            resultado['tempo_verify'] * 1000,
            resultado['tamanho_pk'],
            resultado['tamanho_sk'],
            resultado['tamanho_sig']
        ])

print("\nResultados salvos em 'resultados_benchmarks.csv'")
