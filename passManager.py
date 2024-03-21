import tkinter as tk
import tkinter.messagebox as messagebox
import random
import string
import json
import hashlib
import ast
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

root = tk.Tk()
root.configure  (bg = "#0a043c")
def create_account():
    new_window = tk.Toplevel(root)
    new_window.title("Yeni Hesap Oluştur")
    new_window.geometry("250x200")

    # Kullanıcı adı etiketi
    username_label = tk.Label(new_window, text="Kullanıcı Adı:")
    username_label.pack()

    # Kullanıcı adı giriş alanı
    username_entry = tk.Entry(new_window)
    username_entry.pack()

    # Şifre etiketi
    password_label = tk.Label(new_window, text="Şifre:")
    password_label.pack()

    # Şifre giriş alanı
    password_entry = tk.Entry(new_window, show="*")
    password_entry.pack()

    # Şifreyi doğrulama etiketi
    password_confirm_label = tk.Label(new_window, text="Şifreyi Doğrula:")
    password_confirm_label.pack()

    # Şifreyi doğrulama giriş alanı
    password_confirm_entry = tk.Entry(new_window, show="*")
    password_confirm_entry.pack()

    # Oluştur butonu
    create_button = tk.Button(new_window, text="Oluştur", command=lambda: create_account_action(new_window, username_entry, password_entry, password_confirm_entry))
    create_button.pack()

def create_account_action(new_window, username_entry, password_entry, password_confirm_entry):
    username = username_entry.get()
    password = password_entry.get()
    password_confirm = password_confirm_entry.get()

    # Şifre doğrulaması
    if password != password_confirm:
        messagebox.showerror("Hata", "Şifreler eşleşmiyor. Lütfen tekrar deneyin.")
        return

    # Burada kullanıcı adı ve şifre verilerini kaydetme işlemlerinizi yapabilirsiniz.

    data = dict()
    KEY = convert_key(password)
    ciphertext = encrypt_dict(str(data), KEY)
    ciphertext = ciphertext.decode("ISO-8859-1")
    try:
        with open(f'{username}.json', 'w') as f:
            json.dump(ciphertext, f)
    except Exception as e:
        messagebox.showinfo(f"Dosya yazma hatası: {e}")
    else:
        messagebox.showinfo("Başarılı", "Hesap başarıyla oluşturuldu.")
    new_window.destroy()


def encrypt_dict(data, KEY):
    data = pad(data.encode("utf-8"), AES.block_size)
    cipher = AES.new(KEY, AES.MODE_ECB)
    ciphertext = cipher.encrypt(data)
    return ciphertext

def decrypt_dict(ciphertext, KEY):
    cipher = AES.new(KEY, AES.MODE_ECB)
    data = cipher.decrypt(ciphertext)
    data = unpad(data, AES.block_size).decode("utf-8")
    return data

def convert_key(key):
    hashed_key = hashlib.sha256(key.encode()).digest()[:32]
    return hashed_key

def checkkey(username_entry, password_entry):
    user = username_entry.get()
    key = password_entry.get()
    KEY = convert_key(key)
    
    try:
        with open(f'{user}.json', 'r') as f:
            data_json = json.load(f)
    except Exception as e:
        print(f"Dosya okuma hatası: {e}")
    else:
        print(data_json)
        data_json = data_json.encode("ISO-8859-1")
        try:
            data = decrypt_dict(data_json, KEY)
        except Exception as e:
            messagebox.showerror(f"Şifre hatası: {e}")
        else:
            # print(data)
            print("Başarıyla giriş yapıldı."),
            login(user, KEY, data)

def login(username_entry, password_entry,data):
    data = ast.literal_eval(data)
    def add_password(website, username, password, data):
        data[website]=[username, password]
        

    def lock_and_save(username, password, data):
        # key = input("Şifrenizi giriniz: ")
        # KEY = convert_key(key)
        KEY = password
        ciphertext = encrypt_dict(str(data), KEY)
        ciphertext = ciphertext.decode("ISO-8859-1")
        try:
            with open(f'{username}.json', 'w') as f:
                json.dump(ciphertext, f)
        except Exception as e:
            messagebox.showinfo(f"Dosya yazma hatası: {e}")
        else:
            print("Başarıyla kaydedildi."+username)
            messagebox.showinfo("Başarılı", "Hesap başarıyla eklendi.")
        
    
    def save_account(username, password, data):
        add_password(entry_website.get(), entry_username.get(), entry_password.get(), data)
        lock_and_save(username, password, data)

    def generate_password():
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(chars) for i in range(12))
        entry_password.delete(0, tk.END)
        entry_password.insert(0, password)
    def fill_username():
        website = entry_website.get()
        if website in data:
            info = data[website]
            entry_username.delete(0, tk.END)
            entry_username.insert(0, info[0])
            entry_password.delete(0, tk.END)
            entry_password.insert(0, info[1])
        else:
            messagebox.showerror("Hata", f"'{website}' websitesi bulunamadı.")
    window = tk.Toplevel(root)
    window.title("Yeni Kayıt Oluştur")

    label_website = tk.Label(window, text="Website:")
    label_website.grid(row=0, column=0, padx=10, pady=10)

    entry_website = tk.Entry(window)
    entry_website.grid(row=0, column=1, padx=10, pady=10)

    fill_username_button = tk.Button(window, text="Arşivde Ara", command=fill_username)
    fill_username_button.grid(row=0, column=2, padx=10, pady=10)

    label_username = tk.Label(window, text="Kullanıcı Adı:")
    label_username.grid(row=1, column=0, padx=10, pady=10)

    entry_username = tk.Entry(window)
    entry_username.grid(row=1, column=1, padx=10, pady=10)

    label_password = tk.Label(window, text="Şifre:")
    label_password.grid(row=2, column=0, padx=10, pady=10)

    entry_password = tk.Entry(window)
    entry_password.grid(row=2, column=1, padx=10, pady=10)

    generate_password_button = tk.Button(window, text="Şifre Öner", command=generate_password)
    generate_password_button.grid(row=2, column=2, padx=10, pady=10)

    save_button = tk.Button(window, text="Kaydet", command=lambda:save_account(username_entry, password_entry, data))
    save_button.grid(row=3, columnspan=3, pady=10)



def main_window():
    root.geometry("450x500")
    root.title("Giriş Ekranı")

    username_label = tk.Label(root, text="Kullanıcı Adı:")
    username_label.pack()
    username_label.place(relx=0.5, rely=0.25, anchor="center")

    username_entry = tk.Entry(root)
    username_entry.pack()
    username_entry.place(relx=0.5, rely=0.3, anchor="center")

    password_label = tk.Label(root, text="Şifre:")
    password_label.pack()
    password_label.place(relx=0.5, rely=0.45, anchor="center")

    password_entry = tk.Entry(root, show="*")
    password_entry.pack()
    password_entry.place(relx=0.5, rely=0.5, anchor="center")

    login_button = tk.Button(root, text="Giriş Yap", command=lambda:checkkey(username_entry, password_entry))
    login_button.pack()
    login_button.place(relx=0.5, rely=0.6, anchor="center")

    create_account_button = tk.Button(root, text="Yeni Kayıt Oluştur", command=create_account)
    create_account_button.pack()
    create_account_button.place(relx=0.5, rely=0.7, anchor="center")

    root.mainloop()

main_window()




