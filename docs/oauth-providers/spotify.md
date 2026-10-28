# Spotify

## English

**Protocol:** Spotify OAuth 2.0 authorization-code flow.

1. Register an app and HTTPS callback. Request `user-read-email` and
   `user-read-private`.
2. Redirect with state and PKCE, retain both server-side, and validate state
   before code exchange.
3. Exchange the code using HTTP Basic client authentication and call
   `/v1/me`.
4. Use the Spotify account `id` as subject. Spotify's profile email is not
   treated as a verified-email claim; auto-provisioning is disabled.
5. Explicitly link the identity from an authenticated local session to enable
   later sign-ins.

## Українська

**Протокол:** Spotify OAuth 2.0 authorization-code.

1. Зареєструйте app і HTTPS callback. Запитайте `user-read-email` та
   `user-read-private`.
2. Перенаправте зі state і PKCE, збережіть їх на сервері та перевірте state до
   обміну коду.
3. Обміняйте код із HTTP Basic автентифікацією client і викличте `/v1/me`.
4. Використовуйте Spotify account `id` як subject. Email профілю Spotify не
   вважається claim підтвердженої адреси; автоматичне створення акаунта
   вимкнено.
5. Явно прив’яжіть ідентичність з автентифікованої локальної сесії, щоб
   дозволити подальші входи.
