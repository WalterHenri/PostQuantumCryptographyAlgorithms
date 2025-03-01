from qiskit import QuantumCircuit
from qiskit.visualization import plot_histogram
import numpy as np


def bb84_protocolo(n_bits=100, erro_canal=0.05, presenca_eve=False):
    """
    Simula o protocolo BB84 para Distribuição de Chaves Quânticas

    Args:
        n_bits (int): Número de qubits a serem transmitidos
        erro_canal (float): Taxa de erro do canal quântico
        presenca_eve (bool): Se True, simula a presença de um espião

    Returns:
        dict: Dicionário com resultados e estatísticas
    """
    # Alice gera bits aleatórios para a mensagem e escolha de bases
    alice_bits = np.random.randint(0, 2, n_bits)
    alice_bases = np.random.randint(0, 2, n_bits)

    # Bob escolhe bases aleatórias para medição
    bob_bases = np.random.randint(0, 2, n_bits)

    # Lista para armazenar os resultados da medição de Bob
    bob_resultados = []

    # Simulador quântico
    simulator = Aer.get_backend('qasm_simulator')

    # Para cada bit, Alice prepara um qubit e Bob mede
    for i in range(n_bits):
        qc = QuantumCircuit(1, 1)

        # Alice codifica seu bit
        if alice_bits[i] == 1:
            qc.x(0)  # Aplica porta X se o bit for 1

        # Se Alice usar a base Hadamard
        if alice_bases[i] == 1:
            qc.h(0)  # Aplica porta Hadamard

        # Simulação de espião (Eve)
        if presenca_eve:
            # Eve mede em uma base aleatória e reenvia
            eve_base = np.random.randint(0, 2)
            if eve_base == 1 and alice_bases[i] == 0:
                qc.h(0)  # Eve mudar para base Hadamard
            elif eve_base == 0 and alice_bases[i] == 1:
                qc.h(0)  # Eve mudar para base computacional

            # Eve mede e prepara novo estado
            qc.measure(0, 0)
            qc.reset(0)

            # Eve reenvia o que mediu
            resultado = execute(qc, simulator, shots=1).result().get_counts()
            bit_medido = int(list(resultado.keys())[0])
            if bit_medido == 1:
                qc = QuantumCircuit(1, 1)
                qc.x(0)
            else:
                qc = QuantumCircuit(1, 1)

            # Eve reenvia na base que ela acha que foi a original
            if eve_base == 1:
                qc.h(0)

        # Simulação de erro no canal
        if np.random.random() < erro_canal:
            qc.x(0)  # Bit flip com probabilidade erro_canal

        # Bob mede na sua base escolhida
        if bob_bases[i] == 1:  # Base Hadamard
            qc.h(0)

        qc.measure(0, 0)

        # Executa o circuito e obtém resultados
        resultado = execute(qc, simulator, shots=1).result().get_counts()

        # Armazena o resultado de Bob
        bit_medido = int(list(resultado.keys())[0])
        bob_resultados.append(bit_medido)

    # Converte para numpy array para facilitar operações
    bob_resultados = np.array(bob_resultados)

    # Determina quais bits mantêm (onde as bases coincidem)
    mesma_base = alice_bases == bob_bases

    # Bits da chave peneirada (sifted key)
    alice_chave = alice_bits[mesma_base]
    bob_chave = bob_resultados[mesma_base]

    # Verifica taxa de erro
    taxa_erro = np.sum(alice_chave != bob_chave) / len(alice_chave) if len(alice_chave) > 0 else 0

    return {
        'alice_bits': alice_bits,
        'bob_resultados': bob_resultados,
        'alice_chave': alice_chave,
        'bob_chave': bob_chave,
        'taxa_erro': taxa_erro,
        'tamanho_chave': len(alice_chave)
    }


# Executa simulação sem espião
resultado_sem_eve = bb84_protocolo(n_bits=1000, erro_canal=0.05, presenca_eve=False)
print(
    f"Sem espião: Taxa de erro: {resultado_sem_eve['taxa_erro']:.4f}, Tamanho da chave: {resultado_sem_eve['tamanho_chave']}")

# Executa simulação com espião
resultado_com_eve = bb84_protocolo(n_bits=1000, erro_canal=0.05, presenca_eve=True)
print(
    f"Com espião: Taxa de erro: {resultado_com_eve['taxa_erro']:.4f}, Tamanho da chave: {resultado_com_eve['tamanho_chave']}")
