<img width="1024" height="559" alt="image" src="https://github.com/user-attachments/assets/db508bd9-a7c2-4972-bcf3-c81f14c8861e" />


# CipherForge
D-Link AQUILA PRO AI AX3000 智能 Mesh 路由器/产品型号M30 M30A1_FW1.10固件的 AES-128-CBC 解密工具，支持硬编码固定 Key 与 OpenSSL KDF 派生模式，提供 Python 脚本和 Windows exe 一键版/M30A1_FW1.10 firmware AES-128-CBC decryption tool, supporting hard-coded fixed keys and OpenSSL KDF derivation mode, providing both Python script and Windows executable one-click version


# 🔓 CipherForge

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

**CipherForge** 是一个灵活的 Python 解密工具，专为处理基于 **AES-128-CBC** 算法和 **OpenSSL 标准 KDF 派生机制** 的文件而设计。它针对 M30A1_FW1.10 固件进行解密，支持固定密钥解密与动态派生模式。

**CipherForge** is a versatile Python decryption tool specifically designed to handle files encrypted with the **AES-128-CBC** algorithm and the **OpenSSL standard KDF derivation mechanism**. It is intended for decrypting the M30A1_FW1.10 firmware and supports both fixed-key decryption and dynamic derivation modes.

---

## ✨ 功能特性 / Features

| 特性 (Feature) | 描述 (Description) |
| :--- | :--- |
| **🛡️ 算法支持**<br>Algorithm | 完美支持 AES-128-CBC 加密标准。<br>Fully supports the AES-128-CBC encryption standard. |
| **🔑 KDF 标准**<br>KDF Standard | 遵循 OpenSSL `EVP_BytesToKey` (MD5 迭代) 派生机制。<br>Compliant with OpenSSL `EVP_BytesToKey` (MD5 iteration) derivation mechanism. |
| **⚡ M30 优化**<br>M30 Optimization | 内置 M30A1_FW1.10 固件指纹识别，自动应用固定 Key/IV 以确保解密稳定性。<br>Built-in M30 firmware fingerprinting automatically applies fixed Key/IV for stable decryption. |
| **🤖 自动识别**<br>Automation | 自动检测文件头的 `Salted__` 标记并提取 Salt，自动定位密文起始位置。<br>Automatically detects the `Salted__` header, extracts the Salt, and locates the ciphertext start. |
| **📦 免环境运行**<br>Portable | 提供打包好的 Windows `.exe` 版本，无需安装 Python。<br>Pre-packaged Windows `.exe` version available; no Python installation required. |

---

## 🛠️ 环境要求 / Requirements

如果您选择运行 Python 源码：
If running from Python source code:

* **Python:** 3.6+
* **Dependencies:** `pip install cryptography`

---

## 🚀 使用方法 / Usage

### 基础命令格式 / Base Command Syntax

```bash
python CipherForge.py -s <Input File> -k <Key/Password> [Options]


🧠 M30 固件加密原理 / M30 Encryption Logic
M30 固件采用了独特的加密实现： M30 firmware uses a unique encryption implementation:

1、标准基础 (Standard Base): 使用 OpenSSL EVP_BytesToKey (MD5) 结合密码和 Salt 进行运算。
Uses OpenSSL EVP_BytesToKey (MD5) with Password and Salt.

2、固定密钥 (Fixed Key quirk): 尽管使用了 KDF 流程，但最终使用的 Key 和 IV 在特定版本中是固定的。
Despite the KDF process, the actual Key and IV used are fixed in specific versions.

3、工具智能 (Tool Intelligence): CipherForge 在模式 2 下如果检测到特定的 M30 密码，会自动绕过 KDF 计算，直接返回正确的固定 Key/IV，从而保证 100% 解密成功率。
In Mode 2, if CipherForge detects specific M30 passwords, it bypasses KDF and returns the correct fixed Key/IV, ensuring 100% success.

📥 下载 / Download
无需配置 Python 环境，请前往 [Releases] 页面下载 Windows 可执行文件： No Python environment needed? Download the Windows executable from [Releases]:

CipherForge.exe

Disclaimer: This tool is for educational and research purposes only. Please do not use it for illegal activities.
