import os
import secrets
import string
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Встроенный ключ приложения для защиты содержимого файла .R1 (32 байта)
APP_MASTER_KEY = b"\xfa\x89\x1e\xbc\x99\x12\x44\xae\x88\x31\x00\xef\xaa\xbb\xcc\xdd\x11\x22\x33\x44\x55\x66\x77\x88\x99\x00\xaa\xbb\xcc\xdd\xee\xff"
R1_HEADER = b"R1TOKEN"

def generate_token_key(length=1000) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def derive_512bit_keys(token_key: str, salt: bytes):
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        info=b"file-encryption-v1",
    )
    derived = hkdf.derive(token_key.encode('utf-8'))
    return derived[:32], derived[32:]

def pack_r1_token(token_key: str) -> bytes:
    """Шифрует токен-ключ и упаковывает его в бинарный формат R1"""
    nonce = os.urandom(12)
    aes = AESGCM(APP_MASTER_KEY)
    encrypted_payload = aes.encrypt(nonce, token_key.encode('utf-8'), None)
    return R1_HEADER + nonce + encrypted_payload

def unpack_r1_token(r1_bytes: bytes) -> str:
    """Проверяет заголовок и расшифровывает токен-ключ из файла R1"""
    if not r1_bytes.startswith(R1_HEADER):
        raise ValueError("Неверный формат файла ключа (требуется сигнатура R1)")
    
    header_len = len(R1_HEADER)
    nonce = r1_bytes[header_len:header_len + 12]
    encrypted_payload = r1_bytes[header_len + 12:]
    
    aes = AESGCM(APP_MASTER_KEY)
    token_key_bytes = aes.decrypt(nonce, encrypted_payload, None)
    return token_key_bytes.decode('utf-8')

def encrypt_file(file_path: str):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        token_key = generate_token_key(1000)
        salt = os.urandom(16)
        nonce1 = os.urandom(12)
        nonce2 = os.urandom(12)

        k1, k2 = derive_512bit_keys(token_key, salt)

        aes1 = AESGCM(k1)
        aes2 = AESGCM(k2)
        stage1 = aes1.encrypt(nonce1, data, None)
        ciphertext = aes2.encrypt(nonce2, stage1, None)

        # Сохранение .enc
        enc_path = file_path + ".enc"
        with open(enc_path, "wb") as f:
            f.write(salt + nonce1 + nonce2 + ciphertext)

        # Сохранение зашифрованного токен-файла формата .R1
        r1_path = file_path + ".R1"
        r1_data = pack_r1_token(token_key)
        with open(r1_path, "wb") as f:
            f.write(r1_data)

        return enc_path, r1_path
    except Exception as e:
        raise RuntimeError(f"Ошибка при шифровании: {e}")

def decrypt_file(enc_path: str, r1_path: str):
    try:
        if not r1_path.lower().endswith(".r1"):
            raise ValueError("Файл ключа должен иметь расширение .R1")

        # 1. Чтение и дешифровка файла ключа формата .R1
        with open(r1_path, "rb") as f:
            r1_content = f.read()
        token_key = unpack_r1_token(r1_content)

        # 2. Чтение шифротекста
        with open(enc_path, "rb") as f:
            content = f.read()

        salt = content[:16]
        nonce1 = content[16:28]
        nonce2 = content[28:40]
        ciphertext = content[40:]

        # 3. Деривация ключей
        k1, k2 = derive_512bit_keys(token_key, salt)

        # 4. Расшифровка целевого файла
        aes2 = AESGCM(k2)
        aes1 = AESGCM(k1)
        stage1 = aes2.decrypt(nonce2, ciphertext, None)
        original_data = aes1.decrypt(nonce1, stage1, None)

        out_path = enc_path[:-4] if enc_path.endswith(".enc") else enc_path + ".decrypted"
        with open(out_path, "wb") as f:
            f.write(original_data)

        return out_path
    except Exception as e:
        raise RuntimeError(f"Не удалось расшифровать: неверный/поврежденный файл .R1 или .enc ({e})")

# --- Графический интерфейс ---
class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("R1 Crypto System")
        self.root.geometry("540x420")
        self.root.resizable(False, False)

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_enc = ttk.Frame(notebook)
        notebook.add(self.tab_enc, text="Зашифровать")
        self.build_enc_tab()

        self.tab_dec = ttk.Frame(notebook)
        notebook.add(self.tab_dec, text="Расшифровать")
        self.build_dec_tab()

    def build_enc_tab(self):
        frame = ttk.LabelFrame(self.tab_enc, text=" Создание защищенного файла и токена R1 ")
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        self.enc_file_var = tk.StringVar()
        ttk.Label(frame, text="Файл:").pack(anchor="w", padx=5, pady=5)
        ttk.Entry(frame, textvariable=self.enc_file_var, width=52).pack(fill="x", padx=5, pady=2)
        ttk.Button(frame, text="Обзор...", command=self.select_enc_file).pack(anchor="e", padx=5, pady=5)

        ttk.Button(frame, text="🔒 Зашифровать (Создать .enc и .R1)", command=self.run_encrypt).pack(pady=20)
        self.enc_status = ttk.Label(frame, text="", foreground="gray")
        self.enc_status.pack()

    def build_dec_tab(self):
        frame = ttk.LabelFrame(self.tab_dec, text=" Расшифровка через защищенный ключ R1 ")
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        self.dec_file_var = tk.StringVar()
        ttk.Label(frame, text="Зашифрованный файл (.enc):").pack(anchor="w", padx=5, pady=2)
        ttk.Entry(frame, textvariable=self.dec_file_var, width=52).pack(fill="x", padx=5, pady=2)
        ttk.Button(frame, text="Выбрать .enc", command=self.select_dec_file).pack(anchor="e", padx=5, pady=2)

        self.r1_file_var = tk.StringVar()
        ttk.Label(frame, text="Зашифрованный файл токена (.R1):").pack(anchor="w", padx=5, pady=2)
        ttk.Entry(frame, textvariable=self.r1_file_var, width=52).pack(fill="x", padx=5, pady=2)
        ttk.Button(frame, text="Выбрать ключ .R1", command=self.select_r1_file).pack(anchor="e", padx=5, pady=2)

        ttk.Button(frame, text="🔓 Расшифровать с помощью R1", command=self.run_decrypt).pack(pady=15)

    def select_enc_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.enc_file_var.set(path)

    def select_dec_file(self):
        path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
        if path:
            self.dec_file_var.set(path)
            auto_r1 = path.replace(".enc", "") + ".R1"
            if os.path.exists(auto_r1):
                self.r1_file_var.set(auto_r1)

    def select_r1_file(self):
        path = filedialog.askopenfilename(filetypes=[("R1 Token Key", "*.R1;*.r1"), ("All files", "*.*")])
        if path:
            self.r1_file_var.set(path)

    def run_encrypt(self):
        path = self.enc_file_var.get()
        if not path or not os.path.isfile(path):
            messagebox.showwarning("Внимание", "Выберите файл для защиты!")
            return
        try:
            enc, r1 = encrypt_file(path)
            messagebox.showinfo("Успех", f"Файлы созданы:\n\n1. {os.path.basename(enc)}\n2. {os.path.basename(r1)} (Зашифрованный ключ R1)")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def run_decrypt(self):
        enc_path = self.dec_file_var.get()
        r1_path = self.r1_file_var.get()
        if not enc_path or not os.path.isfile(enc_path) or not r1_path or not os.path.isfile(r1_path):
            messagebox.showwarning("Внимание", "Укажите файл .enc и файл ключа .R1!")
            return
        try:
            out_file = decrypt_file(enc_path, r1_path)
            messagebox.showinfo("Успех", f"Файл успешно расшифрован:\n{os.path.basename(out_file)}")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
