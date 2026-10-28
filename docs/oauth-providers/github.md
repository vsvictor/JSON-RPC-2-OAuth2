# GitHub

## English

**Protocol:** GitHub OAuth App authorization-code flow.

1. Register an OAuth App with an exact HTTPS callback. Request `read:user` and
   `user:email`.
2. Redirect with state and PKCE; persist both values in the server session.
3. Exchange the code, request `/user`, then request `/user/emails`.
4. Use the account's numeric/string `id` as subject. Select only an email marked
   both `primary` and `verified` for automatic local account creation.
5. Persist `(github, id)` and return local PASETO tokens.

The email endpoint requires the `user:email` scope. A public profile email by
itself is not accepted as a verified email.

## Українська

**Протокол:** GitHub OAuth App authorization-code.

1. Зареєструйте OAuth App із точним HTTPS callback. Запитайте `read:user` і
   `user:email`.
2. Перенаправте зі state та PKCE; збережіть обидва значення в серверній сесії.
3. Обміняйте код, запитайте `/user`, потім `/user/emails`.
4. Використовуйте `id` акаунта як subject. Для автоматичного створення
   локального акаунта підходить лише email із `primary` та `verified`.
5. Збережіть `(github, id)` і видайте локальні PASETO-токени.

Для endpoint email потрібен scope `user:email`. Email із публічного профілю сам
по собі не вважається підтвердженим.
