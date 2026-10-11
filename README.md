# Регистрация и вход

Лабораторная: регистрация и вход, проверка полей, GET и POST, cookie и PostgreSQL.

## Что нужно

- Node.js 18 или новее
- PostgreSQL на этом компьютере. Пользователь `postgres`, пароль как в `.env.example` (сейчас `12345`)

Если пароль PostgreSQL другой, скопируйте `.env.example` в `.env` и поменяйте `PGPASSWORD`.

## Запуск

```text
npm install
npm start
```

Откройте http://localhost:3000

При первом запуске программа сама создаёт базу `WebLab` и таблицу `users`, если их ещё нет. Пароли в таблице хранятся как bcrypt-хеш.
