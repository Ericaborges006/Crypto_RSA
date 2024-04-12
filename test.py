from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Geração do par de chaves
def gerar_par_de_chaves():
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    chave_publica = chave_privada.public_key()
    
    # Serialização das chaves para armazenamento
    chave_privada_serializada = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    chave_publica_serializada = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return chave_publica_serializada, chave_privada_serializada

# Encriptação
def encriptar_mensagem(mensagem, chave_publica_serializada):
    chave_publica = serialization.load_pem_public_key(
        chave_publica_serializada,
        backend=default_backend()
    )
    mensagem_encriptada = chave_publica.encrypt(
        mensagem.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensagem_encriptada

# Desencriptação
def desencriptar_mensagem(mensagem_encriptada, chave_privada_serializada):
    chave_privada = serialization.load_pem_private_key(
        chave_privada_serializada,
        password=None,
        backend=default_backend()
    )
    mensagem_desencriptada = chave_privada.decrypt(
        mensagem_encriptada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensagem_desencriptada.decode()

#Função para escolher como escrever a mensagem
def escolher_metodo():
    print("Escolha o método de entrada da mensagem:")
    print("1 - Ler a mensagem de um arquivo .txt")
    print("2 - Digitar a mensagem na consola")
    print ("3 - Digitar mensagem e gravar no .txt")
    opcao = input("Digite a opção desejada (1, 2 ou 3): ")

    if opcao == "1":
        with open('mensagem.txt', 'r') as file:
            return file.read()
    elif opcao == "2":
        return input("Digite a mensagem: ")
    elif opcao == "3":
        mensagem = input("Digite a mensagem: ")
        with open('mensagem.txt', 'w') as file:
            file.write(mensagem)
        return mensagem
    else:
        print("Opção inválida. Tente novamente.")
        return None


# Exemplo de uso
chave_publica, chave_privada = gerar_par_de_chaves()
mensagem = escolher_metodo()

if mensagem:
    mensagem_encriptada = encriptar_mensagem(mensagem, chave_publica)
    mensagem_desencriptada = desencriptar_mensagem(mensagem_encriptada, chave_privada)

    print(f"Mensagem original: {mensagem}")
    print(f"Mensagem encriptada: {mensagem_encriptada}")
    print(f"Mensagem desencriptada: {mensagem_desencriptada}")
