# Bitbucket

## English

**Protocol:** Bitbucket OAuth 2.0 authorization-code flow.

1. Configure a Bitbucket OAuth consumer and exact HTTPS callback. Request
   `account` and `email`.
2. Start authorization with state and PKCE; validate state against the
   server-side session on return.
3. Exchange the code using HTTP Basic client authentication. Query `/2.0/user`
   and `/2.0/user/emails`.
4. Use the returned account UUID as subject. Only the email marked
   `is_primary` and `is_confirmed` is eligible for provisioning.
5. Persist `(bitbucket, uuid)` and issue local tokens.

Do not silently link a Bitbucket identity to a pre-existing account by email.

## Українська

**Протокол:** Bitbucket OAuth 2.0 authorization-code.

1. Налаштуйте Bitbucket OAuth consumer і точний HTTPS callback. Запитайте
   `account` та `email`.
2. Почніть авторизацію зі state та PKCE; після повернення звірте state із
   серверною сесією.
3. Обміняйте код із HTTP Basic автентифікацією client. Запитайте `/2.0/user` і
   `/2.0/user/emails`.
4. Використовуйте UUID акаунта як subject. Для створення акаунта підходить
   лише email з `is_primary` та `is_confirmed`.
5. Збережіть `(bitbucket, uuid)` і видайте локальні токени.

Не прив’язуйте Bitbucket identity до наявного акаунта лише через email.
