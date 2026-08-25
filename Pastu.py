import os
import secrets
import string
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def generate_api_key(length=1000) -> str:
    """Генерация надежного текстового ключа (API) длиной 1000 символов"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def derive_512bit_keys(api_key: str, salt: bytes):
    """Деривация 512 бит (64 байта) энтропии: два 256-битных ключа для каскадного шифрования"""
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        info=b"file-encryption-v1",
    )
    derived = hkdf.derive(api_key.encode('utf-8'))
    return derived[:32], derived[32:]

def encrypt_file(file_path: str):
    try:
        # 1. Чтение исходного файла
        with open(file_path, "rb") as f:
            data = f.read()

        # 2. Генерация 1000-символьного API ключа и соли
        api_key = generate_api_key(1000)
        salt = os.urandom(16)
        nonce1 = os.urandom(12)
        nonce2 = os.urandom(12)

        # 3. Деривация 512-битного ключа (2 x 256 бит)
        k1, k2 = derive_512bit_keys(api_key, salt)

        # 4. Каскадное шифрование AES-256-GCM
        aes1 = AESGCM(k1)
        aes2 = AESGCM(k2)
        stage1 = aes1.encrypt(nonce1, data, None)
        ciphertext = aes2.encrypt(nonce2, stage1, None)

        # 5. Сохранение зашифрованного файла (.enc)
        enc_path = file_path + ".enc"
        with open(enc_path, "wb") as f:
            # Записываем метаданные (salt + nonces) + шифротекст
            f.write(salt + nonce1 + nonce2 + ciphertext)

        # 6. Сохранение API ключа в текстовый файл рядом
        key_path = file_path + ".api_key.txt"
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(api_key)

        return enc_path, key_path
    except Exception as e:
        raise RuntimeError(f"Ошибка при шифровании: {e}")

def decrypt_file(enc_path: str, key_path: str):
    try:
        # 1. Чтение API ключа
        with open(key_path, "r", encoding="utf-8") as f:
            api_key = f.read().strip()

        # 2. Чтение зашифрованного файла
        with open(enc_path, "rb") as f:
            content = f.read()

        salt = content[:16]
        nonce1 = content[16:28]
        nonce2 = content[28:40]
        ciphertext = content[40:]

        # 3. Деривация ключей
        k1, k2 = derive_512bit_keys(api_key, salt)

        # 4. Расшифровка
        aes2 = AESGCM(k2)
        aes1 = AESGCM(k1)
        stage1 = aes2.decrypt(nonce2, ciphertext, None)
        original_data = aes1.decrypt(nonce1, stage1, None)

        # 5. Восстановление исходного файла
        out_path = enc_path[:-4] if enc_path.endswith(".enc") else enc_path + ".decrypted"
        with open(out_path, "wb") as f:
            f.write(original_data)

        return out_path
    except Exception as e:
        raise RuntimeError(f"Не удалось расшифровать файл (неверный ключ или поврежденный файл): {e}")

# --- Графический интерфейс ---
class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("512-bit File Encryptor")
        self.root.geometry("520x400")
        self.root.resizable(False, False)

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Вкладка шифрования
        self.tab_enc = ttk.Frame(notebook)
        notebook.add(self.tab_enc, text="Зашифровать")
        self.build_enc_tab()

        # Вкладка расшифровки
        self.tab_dec = ttk.Frame(notebook)
        notebook.add(self.tab_dec, text="Расшифровать")
        self.build_dec_tab()

    def build_enc_tab(self):
        frame = ttk.LabelFrame(self.tab_enc, text=" Выберите файл для защиты ")
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        self.enc_file_var = tk.StringVar()
        ttk.Label(frame, text="Файл:").pack(anchor="w", padx=5, pady=5)
        ttk.Entry(frame, textvariable=self.enc_file_var, width=50).pack(fill="x", padx=5, pady=2)
        ttk.Button(frame, text="Обзор...", command=self.select_enc_file).pack(anchor="e", padx=5, pady=5)

        ttk.Button(frame, text="🔒 Зашифровать файл", command=self.run_encrypt).pack(pady=25)
        self.enc_status = ttk.Label(frame, text="", foreground="gray")
        self.enc_status.pack()

    def build_dec_tab(self):
        frame = ttk.LabelFrame(self.tab_dec, text=" Параметры для расшифровки ")
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        self.dec_file_var = tk.StringVar()
        ttk.Label(frame, text="Зашифрованный файл (.enc):").pack(anchor="w", padx=5, pady=2)
        ttk.Entry(frame, textvariable=self.dec_file_var, width=50).pack(fill="x", padx=5, pady=2)
        ttk.Button(frame, text="Выбрать .enc файл", command=self.select_dec_file).pack(anchor="e", padx=5, pady=2)

        self.key_file_var = tk.StringVar()
        ttk.Label(frame, text="Файл ключа (.api_key.txt):").pack(anchor="w", padx=5, pady=2)
        ttk.Entry(frame, textvariable=self.key_file_var, width=50).pack(fill="x", padx=5, pady=2)
        ttk.Button(frame, text="Выбрать файл ключа", command=self.select_key_file).pack(anchor="e", padx=5, pady=2)

        ttk.Button(frame, text="🔓 Расшифровать", command=self.run_decrypt).pack(pady=15)

    def select_enc_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.enc_file_var.set(path)

    def select_dec_file(self):
        path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
        if path:
            self.dec_file_var.set(path)
            # Автоподстановка файла ключа, если он рядом
            auto_key = path.replace(".enc", "") + ".api_key.txt"
            if os.path.exists(auto_key):
                self.key_file_var.set(auto_key)

    def select_key_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.key_file_var.set(path)

    def run_encrypt(self):
        path = self.enc_file_var.get()
        if not path or not os.path.isfile(path):
            messagebox.showwarning("Внимание", "Выберите корректный файл для шифрования!")
            return
        try:
            enc, key = encrypt_file(path)
            messagebox.showinfo("Успех", f"Файл успешно зашифрован!\n\nСоздан файл: {os.path.basename(enc)}\nКлюч API: {os.path.basename(key)}")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def run_decrypt(self):
        enc_path = self.dec_file_var.get()
        key_path = self.key_file_var.get()
        if not enc_path or not os.path.isfile(enc_path) or not key_path or not os.path.isfile(key_path):
            messagebox.showwarning("Внимание", "Укажите зашифрованный файл и файл ключа!")
            return
        try:
            out_file = decrypt_file(enc_path, key_path)
            messagebox.showinfo("Успех", f"Файл восстановлен:\n{os.path.basename(out_file)}")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
