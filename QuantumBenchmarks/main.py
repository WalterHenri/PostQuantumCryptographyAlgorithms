import time
import numpy as np
import csv
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
import matplotlib.pyplot as plt

# Importações para Kyber
from pqcryptography.kyber import Kyber512, Kyber768, Kyber1024

# Importações para Dilithium
from pqcryptography.dilithium import Dilithium2, Dilithium3, Dilithium5

# Importações para SPHINCS+
from pqcryptography.sphincs import SphincsHaraka128fSimple


def benchmark_kyber():
    """Benchmark do Kyber KEM em diferentes níveis de segurança"""
    resultados = {}

    for nivel, kyber_class in {
        "Kyber-512": Kyber512,
        "Kyber-768": Kyber768,
        "Kyber-1024": Kyber1024
    }.items():
        # Medir tempo de geração de chaves
        inicio = time.time()
        public_keys = []
        secret_keys = []
        for _ in range(100):
            kyber = kyber_class()
            public_key, secret_key = kyber.keygen()
            public_keys.append(public_key)
            secret_keys.append(secret_key)
        tempo_keygen = (time.time() - inicio) / 100

        # Medir tempo de encapsulamento
        inicio = time.time()
        ciphertexts = []
        shared_secrets = []
        for i in range(100):
            kyber = kyber_class()
            ciphertext, shared_secret = kyber.encapsulate(public_keys[i])
            ciphertexts.append(ciphertext)
            shared_secrets.append(shared_secret)
        tempo_encaps = (time.time() - inicio) / 100

        # Medir tempo de decapsulamento
        inicio = time.time()
        for i in range(100):
            kyber = kyber_class()
            decrypted_shared_secret = kyber.decapsulate(secret_keys[i], ciphertexts[i])
        tempo_decaps = (time.time() - inicio) / 100

        # Armazenar tamanhos
        tamanho_pk = len(public_keys[0])
        tamanho_sk = len(secret_keys[0])
        tamanho_ct = len(ciphertexts[0])

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

    for nivel, dilithium_class in {
        "Dilithium2": Dilithium2,
        "Dilithium3": Dilithium3,
        "Dilithium5": Dilithium5
    }.items():
        # Medir tempo de geração de chaves
        inicio = time.time()
        public_keys = []
        secret_keys = []
        for _ in range(100):
            dilithium = dilithium_class()
            public_key, secret_key = dilithium.keygen()
            public_keys.append(public_key)
            secret_keys.append(secret_key)
        tempo_keygen = (time.time() - inicio) / 100

        # Mensagem de teste
        mensagem = b"Teste de assinatura digital pos-quantica com Dilithium"

        # Medir tempo de assinatura
        inicio = time.time()
        signatures = []
        for i in range(100):
            dilithium = dilithium_class()
            signature = dilithium.sign(secret_keys[i], mensagem)
            signatures.append(signature)
        tempo_sign = (time.time() - inicio) / 100

        # Medir tempo de verificação
        inicio = time.time()
        for i in range(100):
            dilithium = dilithium_class()
            result = dilithium.verify(public_keys[i], mensagem, signatures[i])
        tempo_verify = (time.time() - inicio) / 100

        # Armazenar tamanhos
        tamanho_pk = len(public_keys[0])
        tamanho_sk = len(secret_keys[0])
        tamanho_sig = len(signatures[0])

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

    sphincs_class = SphincsHaraka128fSimple

    # Medir tempo de geração de chaves
    inicio = time.time()
    public_keys = []
    secret_keys = []
    for _ in range(10):  # SPHINCS+ é mais lento, então fazemos menos iterações
        sphincs = sphincs_class()
        public_key, secret_key = sphincs.keygen()
        public_keys.append(public_key)
        secret_keys.append(secret_key)
    tempo_keygen = (time.time() - inicio) / 10

    # Mensagem de teste
    mensagem = b"Teste de assinatura digital pos-quantica com SPHINCS+"

    # Medir tempo de assinatura
    inicio = time.time()
    signatures = []
    for i in range(10):
        sphincs = sphincs_class()
        signature = sphincs.sign(secret_keys[i], mensagem)
        signatures.append(signature)
    tempo_sign = (time.time() - inicio) / 10

    # Medir tempo de verificação
    inicio = time.time()
    for i in range(10):
        sphincs = sphincs_class()
        result = sphincs.verify(public_keys[i], mensagem, signatures[i])
    tempo_verify = (time.time() - inicio) / 10

    # Armazenar tamanhos
    tamanho_pk = len(public_keys[0])
    tamanho_sk = len(secret_keys[0])
    tamanho_sig = len(signatures[0])

    resultados["SPHINCS+"] = {
        "tempo_keygen": tempo_keygen,
        "tempo_sign": tempo_sign,
        "tempo_verify": tempo_verify,
        "tamanho_pk": tamanho_pk,
        "tamanho_sk": tamanho_sk,
        "tamanho_sig": tamanho_sig
    }

    return resultados


def benchmark_rsa():
    """Benchmark do RSA-2048 para comparação"""
    resultados = {}

    # Medir tempo de geração de chaves
    inicio = time.time()
    for _ in range(5):  # RSA é lento para geração de chaves
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
    tempo_keygen = (time.time() - inicio) / 5

    # Mensagem de teste
    mensagem = b"Teste de criptografia com RSA"

    # Medir tempo de encriptação
    inicio = time.time()
    for _ in range(100):
        encrypted = public_key.encrypt(
            mensagem,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    tempo_encrypt = (time.time() - inicio) / 100

    # Medir tempo de decriptação
    inicio = time.time()
    for _ in range(100):
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    tempo_decrypt = (time.time() - inicio) / 100

    # Armazenar tamanhos (aproximados para RSA-2048)
    tamanho_pk = 294  # Tamanho típico para chave pública RSA-2048
    tamanho_sk = 1192  # Tamanho típico para chave privada RSA-2048
    tamanho_ct = 256  # Tamanho típico para criptograma RSA-2048

    resultados["RSA-2048"] = {
        "tempo_keygen": tempo_keygen,
        "tempo_encrypt": tempo_encrypt,
        "tempo_decrypt": tempo_decrypt,
        "tamanho_pk": tamanho_pk,
        "tamanho_sk": tamanho_sk,
        "tamanho_ct": tamanho_ct
    }

    return resultados


def benchmark_ecdsa():
    """Benchmark do ECDSA P-256 para comparação"""
    resultados = {}

    # Medir tempo de geração de chaves
    inicio = time.time()
    for _ in range(100):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
    tempo_keygen = (time.time() - inicio) / 100

    # Mensagem de teste
    mensagem = b"Teste de assinatura digital com ECDSA"

    # Medir tempo de assinatura
    inicio = time.time()
    for _ in range(100):
        signature = private_key.sign(
            mensagem,
            ECDSA(hashes.SHA256())
        )
    tempo_sign = (time.time() - inicio) / 100

    # Medir tempo de verificação
    inicio = time.time()
    for _ in range(100):
        try:
            public_key.verify(
                signature,
                mensagem,
                ECDSA(hashes.SHA256())
            )
        except Exception:
            pass
    tempo_verify = (time.time() - inicio) / 100

    # Armazenar tamanhos (aproximados para ECDSA P-256)
    tamanho_pk = 65  # Formato não comprimido
    tamanho_sk = 32
    tamanho_sig = 64

    resultados["ECDSA P-256"] = {
        "tempo_keygen": tempo_keygen,
        "tempo_sign": tempo_sign,
        "tempo_verify": tempo_verify,
        "tamanho_pk": tamanho_pk,
        "tamanho_sk": tamanho_sk,
        "tamanho_sig": tamanho_sig
    }

    return resultados


def criar_grafico_comparativo(resultados_kyber, resultados_dilithium, resultados_sphincs, resultados_rsa,
                              resultados_ecdsa):
    """Criar gráficos comparativos dos resultados"""

    # Preparar dados para gráfico de tempos (ms)
    algoritmos = []
    tempos_keygen = []
    tempos_operacao1 = []  # encaps/encrypt/sign
    tempos_operacao2 = []  # decaps/decrypt/verify

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

    # Adicionar dados do RSA
    for nivel, resultado in resultados_rsa.items():
        algoritmos.append(nivel)
        tempos_keygen.append(resultado['tempo_keygen'] * 1000)
        tempos_operacao1.append(resultado['tempo_encrypt'] * 1000)
        tempos_operacao2.append(resultado['tempo_decrypt'] * 1000)

    # Adicionar dados do ECDSA
    for nivel, resultado in resultados_ecdsa.items():
        algoritmos.append(nivel)
        tempos_keygen.append(resultado['tempo_keygen'] * 1000)
        tempos_operacao1.append(resultado['tempo_sign'] * 1000)
        tempos_operacao2.append(resultado['tempo_verify'] * 1000)

    # Criar gráfico de barras para tempos
    x = np.arange(len(algoritmos))
    largura = 0.25

    fig, ax = plt.subplots(figsize=(14, 10))
    rects1 = ax.bar(x - largura, tempos_keygen, largura, label='Geração de Chaves')
    rects2 = ax.bar(x, tempos_operacao1, largura, label='Encaps/Encrypt/Sign')
    rects3 = ax.bar(x + largura, tempos_operacao2, largura, label='Decaps/Decrypt/Verify')

    ax.set_ylabel('Tempo (ms)')
    ax.set_title('Comparação de Desempenho de Algoritmos Criptográficos')
    ax.set_xticks(x)
    ax.set_xticklabels(algoritmos)
    ax.legend()

    # Definir escala logarítmica devido à grande variação nos tempos
    ax.set_yscale('log')

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
            plt.savefig('benchmark_algoritmos_tempo.png', dpi=300)
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

            # Adicionar dados do RSA
            for nivel, resultado in resultados_rsa.items():
                tamanhos_pk.append(resultado['tamanho_pk'])
                tamanhos_sk.append(resultado['tamanho_sk'])
                tamanhos_output.append(resultado['tamanho_ct'])

            # Adicionar dados do ECDSA
            for nivel, resultado in resultados_ecdsa.items():
                tamanhos_pk.append(resultado['tamanho_pk'])
                tamanhos_sk.append(resultado['tamanho_sk'])
                tamanhos_output.append(resultado['tamanho_sig'])

            # Criar gráfico de barras para tamanhos
            fig, ax = plt.subplots(figsize=(14, 10))
            rects1 = ax.bar(x - largura, tamanhos_pk, largura, label='Chave Pública')
            rects2 = ax.bar(x, tamanhos_sk, largura, label='Chave Privada')
            rects3 = ax.bar(x + largura, tamanhos_output, largura, label='Criptograma/Assinatura')

            ax.set_ylabel('Tamanho (bytes)')
            ax.set_title('Comparação de Tamanhos de Algoritmos Criptográficos')
            ax.set_xticks(x)
            ax.set_xticklabels(algoritmos)
            ax.legend()

            # Definir escala logarítmica devido às grandes diferenças
            ax.set_yscale('log')

            autolabel(rects1)
            autolabel(rects2)
            autolabel(rects3)

            fig.tight_layout()
            plt.savefig('tamanhos_algoritmos_pq.png', dpi=300)
            plt.close()

            return "Gráficos gerados com sucesso"

        def main():
            """Função principal para executar todos os benchmarks"""
            print("Iniciando benchmarks de algoritmos pós-quânticos...")

            # Executar benchmarks
            resultados_kyber = benchmark_kyber()
            print("Benchmark Kyber concluído.")

            resultados_dilithium = benchmark_dilithium()
            print("Benchmark Dilithium concluído.")

            resultados_sphincs = benchmark_sphincs()
            print("Benchmark SPHINCS+ concluído.")

            resultados_rsa = benchmark_rsa()
            print("Benchmark RSA concluído.")

            resultados_ecdsa = benchmark_ecdsa()
            print("Benchmark ECDSA concluído.")

            # Imprimir resultados
            print("\nResultados do benchmark Kyber (KEM):")
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
                print(f"  Tempo médio de verificação: {resultado['tempo_verify'] * 1000:.2f} ms")
                print(f"  Tamanho da chave pública: {resultado['tamanho_pk']} bytes")
                print(f"  Tamanho da chave privada: {resultado['tamanho_sk']} bytes")
                print(f"  Tamanho da assinatura: {resultado['tamanho_sig']} bytes")

            print("\nResultados do benchmark RSA-2048 (Clássico):")
            for nivel, resultado in resultados_rsa.items():
                print(f"{nivel}:")
                print(f"  Tempo médio de geração de chaves: {resultado['tempo_keygen'] * 1000:.2f} ms")
                print(f"  Tempo médio de encriptação: {resultado['tempo_encrypt'] * 1000:.2f} ms")
                print(f"  Tempo médio de decriptação: {resultado['tempo_decrypt'] * 1000:.2f} ms")
                print(f"  Tamanho da chave pública: {resultado['tamanho_pk']} bytes")
                print(f"  Tamanho da chave privada: {resultado['tamanho_sk']} bytes")
                print(f"  Tamanho do criptograma: {resultado['tamanho_ct']} bytes")

            print("\nResultados do benchmark ECDSA P-256 (Clássico):")
            for nivel, resultado in resultados_ecdsa.items():
                print(f"{nivel}:")
                print(f"  Tempo médio de geração de chaves: {resultado['tempo_keygen'] * 1000:.2f} ms")
                print(f"  Tempo médio de assinatura: {resultado['tempo_sign'] * 1000:.2f} ms")
                print(f"  Tempo médio de verificação: {resultado['tempo_verify'] * 1000:.2f} ms")
                print(f"  Tamanho da chave pública: {resultado['tamanho_pk']} bytes")
                print(f"  Tamanho da chave privada: {resultado['tamanho_sk']} bytes")
                print(f"  Tamanho da assinatura: {resultado['tamanho_sig']} bytes")

            # Gerar gráficos comparativos
            try:
                resultado = criar_grafico_comparativo(resultados_kyber, resultados_dilithium, resultados_sphincs,
                                                      resultados_rsa, resultados_ecdsa)
                print(f"\n{resultado}")
            except Exception as e:
                print(f"\nErro ao gerar gráficos: {e}")
                print("Verifique se o matplotlib está instalado: pip install matplotlib")

            # Salvar resultados em arquivo CSV para análise posterior
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

                # Escrever dados RSA
                for nivel, resultado in resultados_rsa.items():
                    writer.writerow([
                        nivel, 'Clássico',
                        resultado['tempo_keygen'] * 1000,
                        resultado['tempo_encrypt'] * 1000,
                        resultado['tempo_decrypt'] * 1000,
                        resultado['tamanho_pk'],
                        resultado['tamanho_sk'],
                        resultado['tamanho_ct']
                    ])

                # Escrever dados ECDSA
                for nivel, resultado in resultados_ecdsa.items():
                    writer.writerow([
                        nivel, 'Clássico',
                        resultado['tempo_keygen'] * 1000,
                        resultado['tempo_sign'] * 1000,
                        resultado['tempo_verify'] * 1000,
                        resultado['tamanho_pk'],
                        resultado['tamanho_sk'],
                        resultado['tamanho_sig']
                    ])

            print("\nResultados salvos em 'resultados_benchmarks.csv'")

        if __name__ == "__main__":
            main()