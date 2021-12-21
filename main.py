# python main.py -gen gen symmetric_key.txt public_key.txt private_key.txt initial_file.txt encrypted_file.txt decrypted_file.txt iv.txt
# python main.py -enc enc symmetric_key.txt public_key.txt private_key.txt initial_file.txt encrypted_file.txt decrypted_file.txt iv.txt
# python main.py -dec dec symmetric_key.txt public_key.txt private_key.txt initial_file.txt encrypted_file.txt decrypted_file.txt iv.txt

import os
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


# 1. Генерация ключей гибридной системы
def hybrid_key_generation(symmetricKey_path: str,
                asymmetricKeyPublic_path: str,
                asymmetricKeyPrivate_path: str) -> None:
    symmetric_key = os.urandom(16)
    print("Symmetric key generated")

    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()
    print("Asymmetric keys generated")

    with open(asymmetricKeyPublic_path, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))

    with open(asymmetricKeyPrivate_path, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))
    print("Asymmetric keys serialized")

    text = bytes(symmetric_key)
    dc_text = public_key.encrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=None))
    with open(symmetricKey_path, 'wb') as file:
        file.write(dc_text)
    print("The symmetric key is encrypted with the public key")


# 2. Шифрование данных гибридной системой
def hybrid_data_encryption(text_path: str,
                           asymmetricKeyPrivate_path: str,
                           symmetricKey_path: str,
                           encryptedText_path: str,
                           iv_path: str) -> None:
    with open(symmetricKey_path, 'rb') as file:
        d_public_key = file.read()
    with open(asymmetricKeyPrivate_path, 'rb') as file:
        d_private_key = serialization.load_pem_private_key(file.read(), password=None)

    symmetrical_key = d_private_key.decrypt(d_public_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))
    print("Symmetric key decrypted")

    with open(text_path, 'r') as file:
        text_to_encrypt = file.read()

    padder = padding2.ANSIX923(32).padder()
    text = bytes(text_to_encrypt, 'UTF-8')
    padded_text = padder.update(text) + padder.finalize()

    iv = os.urandom(8)

    with open(iv_path, 'wb') as file:
        file.write(iv)

    cipher = Cipher(algorithms.IDEA(symmetrical_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text)

    with open(encryptedText_path, 'wb') as file:
        file.write(c_text)
    print("The text is encrypted")


# 3. Дешифрование данных гибридной системой
def hybrid_decryption(encryptedText_path: str,
                      asymmetricKeyPrivate_path: str,
                      symmetricKey_path: str,
                      decryptedText_path: str,
                      iv_path: str) -> None:
    with open(symmetricKey_path, 'rb') as file:
        d_public_key = file.read()
    with open(asymmetricKeyPrivate_path, 'rb') as file:
        d_private_key = serialization.load_pem_private_key(file.read(), password=None)

    symmetrical_key = d_private_key.decrypt(d_public_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))
    print("Symmetric key decrypted")

    with open(encryptedText_path, 'rb') as file:
        text_to_decrypt = file.read()

    with open(iv_path, 'rb') as file:
        iv = file.read()

    cipher = Cipher(algorithms.IDEA(symmetrical_key), modes.CBC(iv))

    decryptor = cipher.decryptor()
    dc_text = decryptor.update(text_to_decrypt) + decryptor.finalize()
    unpadder = padding2.ANSIX923(32).unpadder()
    unpadded_dc_text = unpadder.update(dc_text)

    with open(decryptedText_path, 'w') as file:
        file.write(str(unpadded_dc_text))
    print("The text is decrypted")


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей', dest='generation')
group.add_argument('-enc', '--encryption', help='Запускает режим шифрования', dest='encryption')
group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования', dest='decryption')

parser.add_argument('symmetric_key', help='Симметричный ключ')
parser.add_argument('public_key', help='Открытый ассиметричный ключ')
parser.add_argument('private_key', help='Закрытый ассиметричный ключ')
parser.add_argument('initial_file', help='Текст')
parser.add_argument('encrypted_file', help='Зашифрованный текст')
parser.add_argument('decrypted_file', help='Расшифрованный текст')

parser.add_argument('iv_path', help='IV')


args = parser.parse_args()

if args.generation is not None:
    hybrid_key_generation(args.symmetric_key, args.public_key, args.private_key)

if args.encryption is not None:
    hybrid_data_encryption(args.initial_file, args.private_key, args.symmetric_key, args.encrypted_file, args.iv_path)

if args.decryption is not None:
    hybrid_decryption(args.encrypted_file, args.private_key, args.symmetric_key, args.decrypted_file, args.iv_path)
