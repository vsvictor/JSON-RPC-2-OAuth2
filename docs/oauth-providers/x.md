# X

## English

**Protocol:** X OAuth 2.0 authorization-code flow with PKCE.

1. Register a confidential OAuth app and exact HTTPS callback. Request the
   `users.read` scope.
2. Redirect to X with PKCE S256 and state; store state/verifier server-side.
3. Exchange the code using the OAuth client credentials and verifier.
4. Query `/2/users/me`; the returned stable user `id` is the provider subject.
   Standard profile access does not provide email.
5. The flow may sign in an identity explicitly linked earlier. It cannot
   auto-provision an account based on email; link through an authenticated
   local session.

Do not treat a username or display name as a stable identifier.

## Українська

**Протокол:** X OAuth 2.0 authorization-code із PKCE.

1. Зареєструйте confidential OAuth app і точний HTTPS callback. Запитайте
   scope `users.read`.
2. Перенаправте на X із PKCE S256 та state; зберігайте state/verifier на
   сервері.
3. Обміняйте код з OAuth client credentials і verifier.
4. Запитайте `/2/users/me`; стабільний `id` користувача є subject провайдера.
   Стандартний профіль не надає email.
5. Потік може виконати вхід для раніше явно прив’язаної ідентичності. Створити
   акаунт за email автоматично неможливо; прив’язування виконуйте в
   автентифікованій локальній сесії.

Не використовуйте username чи display name як стабільний ідентифікатор.
