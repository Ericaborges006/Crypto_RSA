from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives import serialization
#VER ALGORITMO DE CRIPTOGRAFIA RSA

#gerar o par de chaves para o remetente e o destinatário (a pública pode ser compartilhada mas a privada deve ser mantida em segredo)
key = RSA.generate(2048);            #2048 bits
private_key = key.export_key()
public_key = key.public_key().export_key()

#Salvar e carregar estas chaves (guardar num arquivo e carrga las quando for necessário)
#SAVE PRIVATE KEY
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL, #O CHAT TINHA PKCS8
        encryption_algorithm=serialization.BestAvailableEncryption(b"mypassword"),
    ))
#SAVE PUBLIC KEY
with open("public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

#Encriptar a mensagem com a chave pública do destinatário (apenas a chave privada vai poder desencriptar isto)
message = b'Hello World'
public_key_obj = RSA.import_key(public_key)
cipher = PKCS1_OAEP.new(public_key_obj)
ciphertext = cipher.encrypt(message)


#Carregar a chave privada do destinatário
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=b"mypassword",
    )

#Desencriptar a mensagem com a chave privada do destinatário
    original_message = cipher.decrypt(ciphertext)


#Imprimir a mensagem original
print(original_message)
