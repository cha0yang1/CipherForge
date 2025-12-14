import sys
import argparse
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# --- 1. M30 专用常量 ---
M30_PASSWORD_HEX = "b4517d9b98e04d9f075f5e78c743e097"
M30_FINAL_KEY_HEX = "B9226D8C159A2B72A5A19370FED9359B"
M30_FINAL_IV_HEX = "CD50AE7CEB53AB3476B9F46F52D05CFA"

# --- 2. 固件的固定参数 / 默认值 ---
DEFAULT_IV_HEX = "CD50AE7CEB53AB3476B9F46F52D05CFA"
SALT_LENGTH = 8              
SALTED_MAGIC = b'Salted__'   
AES_BLOCK_SIZE = 16          
KEY_SIZE = 16
IV_SIZE = 16

# --- 3. 派生和识别函数 ---

def derive_key_iv_openssl_md5(password_input, salt_hex, key_size, iv_size):
    """
    【模式 2 KDF 逻辑】
    包含 M30 专用覆盖逻辑，确保稳定解密。
    """
    
    # *** M30 固件专用集成: 覆盖 KDF 计算 ***
    if password_input == M30_PASSWORD_HEX:
        print("[*] 检测到 M30 固件专用 Password，直接使用固定 Key/IV。")
        return M30_FINAL_KEY_HEX, M30_FINAL_IV_HEX
    # ***********************************
    
    # 标准 OpenSSL MD5 KDF 逻辑 (用于其他文件)
    password_bytes = password_input.encode('utf-8')
    
    try:
        salt_bytes = binascii.unhexlify(salt_hex)
    except Exception:
        raise ValueError("Salt Hex 格式错误或长度不是 16 位 (8 字节)")

    needed_bytes = key_size + iv_size
    key_iv_bytes = b''
    current_hash_input = password_bytes + salt_bytes
    
    while len(key_iv_bytes) < needed_bytes:
        digest = hashes.Hash(hashes.MD5(), backend=default_backend())
        digest.update(current_hash_input)
        
        current_hash_result = digest.finalize()
        key_iv_bytes += current_hash_result
        
        current_hash_input = current_hash_result + password_bytes + salt_bytes

    key_bytes = key_iv_bytes[:key_size]
    iv_bytes = key_iv_bytes[key_size:needed_bytes]
    
    return binascii.hexlify(key_bytes).decode(), binascii.hexlify(iv_bytes).decode()


def find_salt_start(data):
    """查找文件头部的 'Salted__' 标记。"""
    try:
        magic_index = data.index(SALTED_MAGIC)
        salt_start = magic_index + len(SALTED_MAGIC)
        return salt_start
    except ValueError:
        return -1

# --- 4. 解密函数 (主体) ---
def decrypt_firmware(key_hex, iv_hex, user_salt_start, input_file_path, output_file_path):
    """核心解密函数，使用提供的 Key/IV 进行 AES-128-CBC 解密。"""
    
    # 4.1 Key/IV 验证和转换
    if len(key_hex) != 32:
        print(f"[!] 错误: Key 必须是 32 个十六进制字符 (16 字节)。")
        return
    try:
        KEY = binascii.unhexlify(key_hex)
    except binascii.Error:
        print("[!] 错误: Key 包含非十六进制字符。")
        return
        
    if len(iv_hex) != 32:
        print(f"[!] 错误: IV 必须是 32 个十六进制字符 (16 字节)。")
        return
    try:
        IV = binascii.unhexlify(iv_hex)
    except binascii.Error:
        print("[!] 错误: IV 包含非十六进制字符。")
        return

    print(f"[*] 使用 Key (Hex): {key_hex}")
    print(f"[*] 使用 IV (Hex): {iv_hex}")

    # 4.2 读取文件...
    try:
        with open(input_file_path, 'rb') as f:
            encrypted_data = f.read()
    except FileNotFoundError:
        print(f"[!] 错误: 未找到输入文件 {input_file_path}")
        return

    # 4.3 头部识别...
    auto_salt_start = find_salt_start(encrypted_data)

    if auto_salt_start != -1:
        salt_start_offset = auto_salt_start
        print(f"[*] 自动识别到 'Salted__' 标记。Salt 起始地址: {salt_start_offset} 字节")
    else:
        salt_start_offset = user_salt_start
        print(f"[*] 未找到 'Salted__' 标记，使用用户指定 Salt 起始地址: {salt_start_offset} 字节")

    CIPHERTEXT_START_OFFSET = salt_start_offset + SALT_LENGTH
    print(f"[*] 密文起始地址 (跳过头部): {CIPHERTEXT_START_OFFSET} 字节")

    # 4.4 提取密文...
    if len(encrypted_data) <= CIPHERTEXT_START_OFFSET:
        print("[!] 错误: 文件太小，无法提取密文。")
        return

    ciphertext = encrypted_data[CIPHERTEXT_START_OFFSET:]
    initial_length = len(ciphertext)
    print(f"[*] 提取纯密文初始大小: {initial_length} 字节")
    
    # 4.5 长度检查...
    if initial_length % AES_BLOCK_SIZE != 0:
        remainder = initial_length % AES_BLOCK_SIZE
        print(f"[!] 错误：密文长度 {initial_length} 不是 {AES_BLOCK_SIZE} 的整数倍。余数是 {remainder}。")
        return

    # 4.6 解密和写入...
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    decryptor = cipher.decryptor()
    decrypted_data_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 4.7 处理填充
    try:
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_data_padded) + unpadder.finalize()
        print("[*] 解密成功并移除 PKCS#7 填充。")
    except ValueError:
        print("[!] 警告: 填充验证失败。保存带有原始填充的解密数据。")
        decrypted_data = decrypted_data_padded
    
    # 4.8 写入结果
    try:
        with open(output_file_path, 'wb') as f:
            f.write(decrypted_data)
        print(f"[+] 成功! 解密文件已保存到: {output_file_path}")
    except IOError:
        print(f"[!] 错误: 无法写入输出文件 {output_file_path}")

# --- 5. 主程序入口与参数解析 ---
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        description="CipherForge: 混合模式解密工具 (Mode 2 包含 M30 专用稳定集成)",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # 核心参数
    parser.add_argument('-s', '--source', required=True, help="加密输入文件路径")
    parser.add_argument('-d', '--destination', default="decrypted_firmware.bin", help="解密输出文件路径")
    
    # Key 参数 (必须输入)
    parser.add_argument('-k', '--key', required=True, help="【模式1】最终解密 Key (32位Hex)；【模式2】KDF Password 字符串。")
    
    # IV 参数 (固定 IV 作为默认值)
    parser.add_argument('-i', '--iv', default=DEFAULT_IV_HEX, help=f"最终解密 IV (32位Hex)。默认: {DEFAULT_IV_HEX}")

    # Salt 参数 (用于触发 KDF 模式)
    parser.add_argument('-T', '--salt-hex', help="【模式2】用于派生 Key/IV 的 8 字节 Hex Salt 字符串 (16位Hex)。")
    
    # 偏移量参数
    parser.add_argument(
        '-S', '--salt-start', 
        type=int,
        default=8, 
        help="【可选】手动指定 Salt 偏移量。"
    )

    args = parser.parse_args()
    
    # --- 模式切换逻辑 ---
    final_key_hex = args.key
    final_iv_hex = args.iv

    if args.salt_hex:
        # ** 模式 2: KDF 派生模式 (包含 M30 专用覆盖) **
        try:
            if len(args.salt_hex) != 16:
                if len(args.salt_hex) % 2 != 0:
                    raise ValueError("Salt 长度为奇数，必须是 16 位偶数。")
                else:
                    raise ValueError(f"Salt 长度必须是 16 位 Hex (8 字节)。当前长度: {len(args.salt_hex)}")
        except ValueError as e:
            print(f"[!] 错误：Salt 格式不正确或长度错误: {e}")
            sys.exit(1)
            
        print("\n=== 激活 KDF 派生模式 (标准 OpenSSL MD5 + M30 覆盖) ===")
        print(f"[*] KDF Password (来自 -k): {args.key}")
        print(f"[*] KDF Salt (来自 -T):     {args.salt_hex}")

        # 调用 KDF (可能会被 M30 覆盖)
        final_key_hex, final_iv_hex = derive_key_iv_openssl_md5(args.key, args.salt_hex, KEY_SIZE, IV_SIZE)
        
        print(f"[+] 派生 Key (Hex): {final_key_hex}")
        print(f"[+] 派生 IV (Hex):  {final_iv_hex}")
        print("=========================================\n")
        
    else:
        # ** 模式 1: 固定 IV/输入 Key 模式 **
        print("\n=== 激活固定 IV/输入 Key 模式 (用于已知 Key/IV) ===")
        print(f"[*] Key 来自 -k 参数。")
        print(f"[*] IV 使用默认值或 -i 参数。")
        print("=========================================\n")
        
    # ** 运行解密 **
    decrypt_firmware(final_key_hex, final_iv_hex, args.salt_start, args.source, args.destination)
