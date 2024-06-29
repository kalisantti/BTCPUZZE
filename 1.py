import random  
import hashlib
import base58
import time
import ecdsa
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def calculate_wallet_address(private_key):
    """
    Função para calcular o endereço da carteira a partir da chave privada.
    """
    private_key_bytes = bytes.fromhex(private_key)
    public_key_bytes = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key.to_string(
        "compressed")
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    extended_hash = b'\x00' + ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
    binary_address = extended_hash + checksum
    wallet_address = base58.b58encode(binary_address)
    return wallet_address.decode()

def check_private_key(private_key, wallet):
    """
    Função para verificar se uma chave privada corresponde à carteira.
    """
    wallet_prefix = calculate_wallet_address(private_key)[:4]
    if wallet_prefix != wallet[:4]:
        return None
    wallet_address = calculate_wallet_address(private_key)
    if wallet_address == wallet:
        return private_key, wallet_address
    return None

def send_email(subject, body, to_email):
    """
    Função para enviar um e-mail com o resultado.
    """
    from_email = "santticonsul@outlook.com"
    password = "YelsewMI312@!"
    
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp-mail.outlook.com', 587)
        server.starttls()
        server.login(from_email, password)
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()
        print("E-mail enviado com sucesso!")
    except Exception as e:
        print(f"Falha ao enviar e-mail: {e}")

def search_private_key(start_key, stop_key, wallet, keys_before_jump, jump_size, email):
    """
    Função para buscar chave privada usando busca sequencial.
    """
    start_int = int(start_key, 16)
    stop_int = int(stop_key, 16)

    print("\nStarting position:", start_key)

    keys_tested = 0
    start_time = time.time()
    results = process_keys(start_key, stop_key, wallet, keys_before_jump, jump_size, keys_tested)
    end_time = time.time()

    print_results(results)
    elapsed_time = end_time - start_time
    print(f"Tempo de execução real: {elapsed_time} segundos")

    if results:
        subject = "Resultado da busca de chave privada"
        body = f"Chave privada: {results[0][0]}\nEndereço da carteira: {results[0][1]}"
        send_email(subject, body, email)

def process_keys(start_key, stop_key, wallet, keys_before_jump, jump_size, keys_tested):
    """
    Função auxiliar para processar as chaves em um determinado intervalo, usando busca sequencial.
    """
    results = []
    start_int = int(start_key, 16)
    stop_int = int(stop_key, 16)

    i = start_int
    while i <= stop_int:
        private_key = hex(i)[2:].zfill(64)
        result = check_private_key(private_key, wallet)
        keys_tested += 1
        print(f"\rTestando chave privada: {private_key} | Chaves testadas: {keys_tested}", end='', flush=True)
        if result:
            results.append(result)
            break
        if keys_tested == keys_before_jump:
            i += jump_size
            keys_tested = 0
        else:
            i += 1

    return results

def print_results(results):
    """
    Função para imprimir os resultados encontrados durante a busca.
    """
    print("\n=-=-=-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-")
    print("Chaves privadas encontradas:")
    if results:
        for result in results:
            if result:
                print("Private Key:", result[0])
                print("Wallet Address:", result[1])
    else:
        print("Nenhuma chave privada válida encontrada no intervalo especificado.")
    print("=-=-=-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-==-=-=-=-=-=-")

# Solicitar as informações ao usuário e validar as entradas
while True:
    try:
        start_key = input("Digite a Start key em formato hexadecimal: ")
        stop_key = input("Digite a Stop key em formato hexadecimal: ")
        wallet = input("Digite o endereço da carteira (Wallet): ")
        keys_before_jump = int(input("Digite o número de chaves testadas antes do salto: "))
        jump_size = int(input("Digite o tamanho do salto: "))
        email = input("Digite o endereço de e-mail para enviar o resultado: ")

        try:
            int(start_key, 16)
            int(stop_key, 16)
        except ValueError:
            raise ValueError("As chaves fornecidas não estão no formato hexadecimal correto.")

        if len(wallet) != 34 or not wallet.startswith("1"):
            raise ValueError("Endereço da carteira inválido")

        break
    except ValueError as e:
        print("Erro:", e)
        print("Por favor, insira valores válidos.\n")

search_private_key(start_key, stop_key, wallet, keys_before_jump, jump_size, email)
