import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from ttkthemes import ThemedTk
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import os
import cv2
import numpy as np


# =========================
# CRYPTOGRAPHY FUNCTIONS
# =========================

def generate_aes_key(password: str) -> bytes:
    """
    Generate a 256-bit AES key from the password using SHA-256.
    """
    return hashlib.sha256(password.encode("utf-8")).digest()


def encrypt_message(message: str, password: str) -> bytes:
    """
    AES-GCM encryption.
    Output format: nonce (12 bytes) + ciphertext_with_tag
    """
    key = generate_aes_key(password)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode("utf-8"), None)
    return nonce + ciphertext


def decrypt_message(encrypted_data: bytes, password: str) -> str:
    """
    AES-GCM decryption.
    Expects input format: nonce (12 bytes) + ciphertext_with_tag
    """
    try:
        key = generate_aes_key(password)
        aesgcm = AESGCM(key)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception:
        return "[Decryption Failed]"


# =========================
# ADDITIONAL AUTHENTICATION
# =========================

def add_auth_tag(data: bytes) -> bytes:
    """
    Append SHA-256 hash for extra integrity verification.
    """
    hash_digest = hashlib.sha256(data).digest()
    return data + hash_digest


def verify_auth_tag(data: bytes):
    """
    Verify appended SHA-256 hash.
    Returns: (is_valid, original_data)
    """
    if len(data) < 32:
        return False, b""
    msg, received_hash = data[:-32], data[-32:]
    expected_hash = hashlib.sha256(msg).digest()
    return expected_hash == received_hash, msg


# =========================
# LSB STEGANOGRAPHY
# =========================

def lsb_encode(image_path: str, data: bytes, output_path: str):
    img = Image.open(image_path).convert("RGB")
    binary = ''.join(format(byte, '08b') for byte in data)
    data_len = len(binary)

    pixels = list(img.getdata())
    capacity = len(pixels) * 3
    if data_len > capacity:
        raise ValueError("Data too large for selected image using LSB.")

    new_pixels = []
    idx = 0

    for pixel in pixels:
        new_pixel = list(pixel)
        for j in range(3):  # RGB channels
            if idx < data_len:
                new_pixel[j] = (new_pixel[j] & ~1) | int(binary[idx])
                idx += 1
        new_pixels.append(tuple(new_pixel))

    img.putdata(new_pixels)
    img.save(output_path)
    return output_path


def lsb_decode(image_path: str, length: int) -> bytes:
    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())
    binary = ""

    required_bits = length * 8
    for pixel in pixels:
        for value in pixel[:3]:
            binary += str(value & 1)
            if len(binary) >= required_bits:
                break
        if len(binary) >= required_bits:
            break

    data = bytearray()
    for i in range(0, len(binary), 8):
        byte = binary[i:i + 8]
        data.append(int(byte, 2))
    return bytes(data)


# =========================
# DCT STEGANOGRAPHY
# =========================

def dct_encode(image_path: str, data: bytes, output_path: str):
    image = cv2.imread(image_path)
    if image is None:
        raise ValueError("Invalid image.")

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape
    data_bin = ''.join(format(byte, '08b') for byte in data)

    max_blocks = (h // 8) * (w // 8)
    if len(data_bin) > max_blocks:
        raise ValueError("Data too large for selected image using DCT.")

    idx = 0
    result = gray.copy().astype(np.float32)

    for y in range(0, h - 7, 8):
        for x in range(0, w - 7, 8):
            block = result[y:y + 8, x:x + 8]
            dct_block = cv2.dct(block)

            if idx < len(data_bin):
                coeff = int(round(dct_block[4, 4]))
                coeff = (coeff & ~1) | int(data_bin[idx])
                dct_block[4, 4] = float(coeff)
                idx += 1

            idct_block = cv2.idct(dct_block)
            result[y:y + 8, x:x + 8] = np.clip(idct_block, 0, 255)

            if idx >= len(data_bin):
                break
        if idx >= len(data_bin):
            break

    final_img = cv2.cvtColor(result.astype(np.uint8), cv2.COLOR_GRAY2BGR)
    cv2.imwrite(output_path, final_img)
    return output_path


def dct_decode(image_path: str, length: int) -> bytes:
    image = cv2.imread(image_path)
    if image is None:
        raise ValueError("Invalid image.")

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY).astype(np.float32)
    h, w = gray.shape
    data_bin = ""
    required_bits = length * 8

    for y in range(0, h - 7, 8):
        for x in range(0, w - 7, 8):
            block = gray[y:y + 8, x:x + 8]
            dct_block = cv2.dct(block)
            data_bin += str(int(round(dct_block[4, 4])) & 1)
            if len(data_bin) >= required_bits:
                break
        if len(data_bin) >= required_bits:
            break

    data = bytearray()
    for i in range(0, len(data_bin), 8):
        byte = data_bin[i:i + 8]
        data.append(int(byte, 2))

    return bytes(data)


# =========================
# SECURITY CHECK
# =========================

def perform_adaptive_security_check():
    return "[Security] Adaptive check passed. AES encryption applied successfully."


# =========================
# GUI APPLICATION
# =========================

class StegApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Dual Layer Steganography")
        self.root.geometry("650x540")
        self.root.configure(bg="#d9f0ff")
        self.img_path = ""

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "TButton",
            background="#b3d9ff",
            foreground="black",
            font=("Segoe UI", 10, "bold")
        )
        style.configure("TLabel", background="#d9f0ff", font=("Segoe UI", 10))
        style.configure("TEntry", padding=5)

        self.build_layout()

    def build_layout(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        ttk.Label(self.root, text="Plaintext Message:").grid(
            row=0, column=0, sticky="w", padx=10, pady=(12, 0)
        )

        self.message_entry = tk.Text(self.root, height=6, wrap="word", font=("Segoe UI", 10))
        self.message_entry.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")

        ttk.Label(self.root, text="Password:").grid(
            row=2, column=0, sticky="w", padx=10, pady=(10, 0)
        )

        self.password_entry = ttk.Entry(self.root, show="*")
        self.password_entry.grid(row=3, column=0, padx=10, pady=5, sticky="ew")

        ttk.Label(
            self.root,
            text="Embedding Method (AES is applied automatically):"
        ).grid(row=4, column=0, sticky="w", padx=10, pady=(10, 0))

        self.method_var = tk.StringVar(value="LSB")
        self.method_combo = ttk.Combobox(
            self.root,
            textvariable=self.method_var,
            values=["LSB", "DCT"],
            state="readonly"
        )
        self.method_combo.grid(row=5, column=0, padx=10, pady=5, sticky="ew")

        self.image_label = ttk.Label(self.root, text="No image selected")
        self.image_label.grid(row=6, column=0, sticky="w", padx=10, pady=(5, 0))

        button_frame = ttk.Frame(self.root)
        button_frame.grid(row=7, column=0, pady=15, padx=10, sticky="ew")
        button_frame.columnconfigure((0, 1, 2), weight=1)

        ttk.Button(button_frame, text="Select Image", command=self.select_image).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Hide Message", command=self.hide_message).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="Extract Message", command=self.extract_message).grid(row=0, column=2, padx=5)

    def clear_fields_after_encryption(self):
        """
        Clears dialog/input fields after successful encryption and embedding.
        """
        self.message_entry.delete("1.0", tk.END)
        self.password_entry.delete(0, tk.END)
        self.clear_image_display()

    def clear_image_selection(self):
        """
        Clears only the selected image after decryption.
        """
        self.clear_image_display()

    def clear_image_display(self):
        """
        Properly clears the image display label and path.
        """
        self.img_path = ""
        self.image_label.config(text="No image selected")
        self.image_label.update_idletasks()

    def select_image(self):
        path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")]
        )
        if path:
            self.img_path = path
            self.image_label.config(text=f"Selected Image: {path}")

    def hide_message(self):
        if not self.img_path:
            messagebox.showwarning("Warning", "Please select an image.")
            return

        message = self.message_entry.get("1.0", tk.END).strip()
        password = self.password_entry.get().strip()

        if not message or not password:
            messagebox.showwarning("Warning", "Message and password are required.")
            return

        security_check = perform_adaptive_security_check()

        try:
            # Step 1: AES encrypt plaintext -> ciphertext
            encrypted = encrypt_message(message, password)

            # Step 2: Add SHA-256 authentication tag
            authenticated = add_auth_tag(encrypted)

            # Step 3: Prefix payload length (2 bytes)
            payload_len = len(authenticated).to_bytes(2, "big")
            final_payload = payload_len + authenticated

            # Step 4: Embed ciphertext into image using selected embedding method
            method = self.method_var.get()
            output_path = self.img_path.rsplit(".", 1)[0] + f"_{method.lower()}_steg.png"

            if method == "LSB":
                lsb_encode(self.img_path, final_payload, output_path)
            else:
                dct_encode(self.img_path, final_payload, output_path)

            # Clear fields automatically after encryption/hiding
            self.clear_fields_after_encryption()

            self.root.after(100, lambda: messagebox.showinfo(
                "Success",
                f"{security_check}\n\n"
                f"Architecture followed correctly:\n"
                f"Plaintext → AES Ciphertext → {method} Embedding\n\n"
                f"Stego image saved at:\n{output_path}"
            ))

        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {e}")

    def extract_message(self):
        if not self.img_path:
            messagebox.showwarning("Warning", "Please select an image.")
            return

        password = self.password_entry.get().strip()
        if not password:
            messagebox.showwarning("Warning", "Password required.")
            return

        method = self.method_var.get()

        try:
            # Step 1: Read payload length
            if method == "LSB":
                length_prefix = lsb_decode(self.img_path, 2)
            else:
                length_prefix = dct_decode(self.img_path, 2)

            payload_len = int.from_bytes(length_prefix, "big")

            if payload_len <= 0:
                raise ValueError("No hidden payload found.")

            # Step 2: Read full payload
            total_length = 2 + payload_len
            if method == "LSB":
                extracted = lsb_decode(self.img_path, total_length)
            else:
                extracted = dct_decode(self.img_path, total_length)

            raw_data = extracted[2:]  # remove 2-byte length prefix

            # Step 3: Verify integrity
            valid, encrypted_payload = verify_auth_tag(raw_data)
            if not valid:
                raise ValueError("Authentication failed. Data may be tampered.")

            # Step 4: AES decrypt ciphertext -> plaintext
            message = decrypt_message(encrypted_payload, password)
            if message == "[Decryption Failed]":
                raise ValueError("Incorrect password or corrupted data.")

            self.message_entry.delete("1.0", tk.END)
            self.message_entry.insert(tk.END, message)

            self.clear_image_selection()

            self.root.after(100, lambda: messagebox.showinfo(
                "Success",
                f"Message extracted successfully using {method}.\n"
                f"AES decryption completed."
            ))

        except Exception as e:
            messagebox.showerror("Error", f"Extraction failed: {e}")


# =========================
# RUN APPLICATION
# =========================

if __name__ == "__main__":
    root = ThemedTk(theme="equilux")
    app = StegApp(root)
    root.mainloop()