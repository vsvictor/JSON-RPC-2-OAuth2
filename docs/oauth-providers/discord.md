# Discord

## English

**Protocol:** Discord OAuth 2.0 authorization-code flow.

1. Configure an application redirect URL and request `identify email`.
2. Redirect with state and PKCE; store both on the server and compare callback
   state before exchanging the code.
3. Exchange the code and query `/api/users/@me`.
4. Use the immutable Discord user `id` as subject. A new local account requires
   the response's `verified: true` and an email.
5. Persist `(discord, id)` and issue local tokens.

Guild membership or bot authorization is a separate Discord OAuth scope and is
not implied by this identity flow.

## Українська

**Протокол:** Discord OAuth 2.0 authorization-code.

1. Налаштуйте redirect URL застосунку та запитайте `identify email`.
2. Перенаправте зі state і PKCE; зберігайте їх на сервері та перевірте state
   callback до обміну коду.
3. Обміняйте код і запитайте `/api/users/@me`.
4. Використовуйте незмінний Discord user `id` як subject. Новий локальний
   акаунт потребує email і `verified: true`.
5. Збережіть `(discord, id)` і видайте локальні токени.

Членство в guild чи bot authorization потребує окремих Discord OAuth scopes і
не надається цим потоком ідентифікації.
