from telegram import Update, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# Токен бота от @BotFather
TOKEN = "7957467241:AAHQ_cwPzsNaazwofGTSEIdDqPtaNdZ9cEQ"  # Замените на ваш токен
# ID администратора (ваш chat_id)
ADMIN_ID = 6039953497  # Замените на ваш chat_id (например, 123456789)

# Функция для команды /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Создаем постоянную клавиатуру с кнопкой "Отправить Дауну"
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
    username = user.username or user.first_name  # Ник или имя, если ника нет
    message_text = update.message.text

    # Проверяем, нажал ли пользователь кнопку "Отправить Дауну"
    if message_text == "Отправить Дауну":
        # Устанавливаем состояние, что пользователь нажал кнопку
        context.user_data["waiting_for_message"] = True
        await update.message.reply_text("Напиши сообщение, которое хочешь отправить Дауну:")
    elif context.user_data.get("waiting_for_message"):
        # Если ожидается сообщение, пересылаем его администратору
        await context.bot.send_message(
            chat_id=ADMIN_ID,
            text=f"Сообщение от @{username} (ID: {user_id}):\n{message_text}"
        )
        # Подтверждаем пользователю, что сообщение отправлено
        await update.message.reply_text("Сообщение успешно отправлено Дауну!")
        # Сбрасываем состояние
        context.user_data["waiting_for_message"] = False
    else:
        # Игнорируем сообщения, если пользователь не нажал кнопку
        await update.message.reply_text(
            "Пожалуйста, сначала нажми кнопку 'Отправить Дауну' внизу."
        )

# Основная функция для запуска бота
def main():
    # Создаем приложение
    application = Application.builder().token(TOKEN).build()

    # Регистрируем обработчики
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    # Запускаем бота
    print("Бот запущен...")
    application.run_polling()

if __name__ == "__main__":
    main()