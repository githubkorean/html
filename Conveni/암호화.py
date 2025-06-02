import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode
import secrets

# 상수
PASSWORD = b'TEST'
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32  # 256 bits
DATA_DIR = 'Data'
RESULT_DIR = 'image'

def derive_key(password: bytes, salt: bytes) -> bytes:
    """비밀번호로부터 키 도출"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(input_path, output_path, password: bytes):
    # 원본 파일 읽기
    with open(input_path, 'rb') as f:
        data = f.read()

    # 패딩 적용 (AES는 블록 단위 필요)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # 키 도출
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)

    # IV 생성
    iv = secrets.token_bytes(IV_SIZE)

    # 암호화
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # [salt + iv + 암호화된 데이터] 형태로 저장
    with open(output_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)

def main():
    os.makedirs(RESULT_DIR, exist_ok=True)
    for filename in os.listdir(DATA_DIR):
        if filename.lower().endswith('.jpg'):
            input_path = os.path.join(DATA_DIR, filename)
            output_path = os.path.join(RESULT_DIR, filename + '.enc')
            encrypt_file(input_path, output_path, PASSWORD)
            print(f'Encrypted: {filename} -> {output_path}')

if __name__ == '__main__':
    main()
