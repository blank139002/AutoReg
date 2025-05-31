import requests
import os
import json
import asyncio
import re
from datetime import datetime
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# --- Configuration ---
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
DISCORD_CHANNEL_ID = 1376183297440354344
DISCORD_BOT_ID = 1376183314242732134
POLL_INTERVAL = 1
USER_FILE = "users.json"

headers = {
    'Authorization': DISCORD_TOKEN,
    'Content-Type': 'application/json'
}
last_message_id = None

def escape_markdown_v2(text: str) -> str:
    escape_chars = r'\_*[]()~`>#+-=|{}.!'
    return ''.join('\\' + c if c in escape_chars else c for c in text)

def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            try:
                return set(json.load(f))
            except json.JSONDecodeError:
                print(f"Внимание: {USER_FILE} пуст или поврежден.")
                return set()
    return set()

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(list(users), f)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat.id
    users = load_users()
    users.add(chat_id)
    save_users(users)
    context.user_data["notifications"] = True

    keyboard = [[KeyboardButton("Включить уведомления"), KeyboardButton("Выключить уведомления")]]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=False)
    await update.message.reply_text(
        "Бот мониторит Discord-канал. Используй кнопки для управления уведомлениями.",
        reply_markup=reply_markup
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message_text = update.message.text
    if message_text == "Включить уведомления":
        context.user_data["notifications"] = True
        await update.message.reply_text("Уведомления включены.")
    elif message_text == "Выключить уведомления":
        context.user_data["notifications"] = False
        await update.message.reply_text("Уведомления выключены.")
    # Игнорируем всё остальное

async def poll_messages(context: ContextTypes.DEFAULT_TYPE):
    global last_message_id
    users = load_users()
    while True:
        try:
            params = {'limit': 10}
            if last_message_id:
                params['after'] = last_message_id

            response = requests.get(
                f'https://discord.com/api/v10/channels/{DISCORD_CHANNEL_ID}/messages',
                headers=headers,
                params=params
            )
            response.raise_for_status()

            messages = response.json()
            for message in reversed(messages):
                if int(message['author']['id']) == DISCORD_BOT_ID and message.get('embeds'):
                    for embed in message['embeds']:
                        desc = embed.get('description', '')
                        if "<:BottomSlantArrow:1376185049950720137>" in desc and "**Value:**" in desc:
                            match = re.search(r"\*\*Value:\*\*\s*([\d,]+)\$\s*```([\w-]+)```", desc)
                            if match:
                                value_str = match.group(1)
                                try:
                                    numeric_value = int(value_str.replace(',', ''))
                                    if numeric_value >= 10000000000:
                                        code = match.group(2)
                                        escaped_code = escape_markdown_v2(code)
                                        text = f"💸 Value: {value_str}\n`{escaped_code}`"
                                        print(f"Новое сообщение: {text}")
                                        for chat_id in users:
                                            if context.bot_data.get(f"notifications_{chat_id}", True):
                                                try:
                                                    await context.bot.send_message(
                                                        chat_id=chat_id,
                                                        text=text,
                                                        parse_mode='MarkdownV2'
                                                    )
                                                except Exception as e:
                                                    print(f"Ошибка отправки {chat_id}: {e}")
                                    else:
                                        print(f"Пропущено: Value {value_str} < 10B")
                                except ValueError:
                                    print(f"Ошибка преобразования '{value_str}'")
                last_message_id = message['id']
            await asyncio.sleep(POLL_INTERVAL)
        except requests.exceptions.RequestException as e:
            print(f"Ошибка сети: {e}")
            await asyncio.sleep(POLL_INTERVAL * 2)
        except Exception as e:
            print(f"Ошибка опроса: {e}")
            await asyncio.sleep(POLL_INTERVAL * 2)

def main():
    application = Application.builder().token(TELEGRAM_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.job_queue.run_repeating(poll_messages, interval=POLL_INTERVAL)
    print("Бот запущен...")
    application.run_polling()

if __name__ == "__main__":
    main()