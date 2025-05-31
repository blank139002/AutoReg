from telegram import Update, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# Токен бота и ID администратора
TOKEN = "7957467241:AAHQ_cwPzsNaazwofGTSEIdDqPtaNdZ9cEQ"
ADMIN_ID = 6039953497

# Команда /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [[KeyboardButton("Отправить Дауну")]]
    reply_markup = ReplyKeyboardMarkup(
        keyboard, resize_keyboard=True, one_time_keyboard=False
    )
    await update.message.reply_text(
        "Нажми кнопку 'Отправить Дауну' внизу, чтобы отправить сообщение:",
        reply_markup=reply_markup
    )

# Обработчик текстовых сообщений
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.message.from_user
    user_id = user.id
    username = user.username or user.first_name
    message_text = update.message.text

    if message_text == "Отправить Дауну":
        context.user_data["waiting_for_message"] = True
        await update.message.reply_text("Напиши сообщение, которое хочешь отправить Дауну:")
    elif context.user_data.get("waiting_for_message"):
        await context.bot.send_message(
            chat_id=ADMIN_ID,
            text=f"Сообщение от @{username} (ID: {user_id}):\n{message_text}"
        )
        await update.message.reply_text("Сообщение успешно отправлено Дауну!")
        context.user_data["waiting_for_message"] = False
    else:
        await update.message.reply_text(
            "Пожалуйста, сначала нажми кнопку 'Отправить Дауну' внизу."
        )

# Основная функция
def main():
    application = Application.builder().token(TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("Бот запущен...")
    application.run_polling()

if __name__ == "__main__":
    main()