# Apple

## English

**Protocol:** Sign in with Apple authorization-code flow with PKCE and an
Apple client-secret JWT.

1. Register a Services ID and HTTPS return URL with Apple.
2. Start the authorization flow with `name email` scopes, `state`, and PKCE.
3. Store the state/verifier in the server session; validate state on callback.
4. Exchange the code at Apple using the provider-generated client-secret JWT.
5. Verify the returned ID token's RS256 signature using Apple's JWKS and check
   issuer, audience, and expiry.
6. Persist `(apple, sub)`. Provisioning requires the Apple `email` and
   `email_verified` claim; Apple may only provide the name/email on first consent.

Treat the Apple private key and client-secret JWT as server secrets. Do not
rely on client-submitted name/email fields.

## Українська

**Протокол:** authorization-code Sign in with Apple з PKCE та Apple
client-secret JWT.

1. Зареєструйте Services ID і HTTPS return URL у Apple.
2. Почніть вхід зі scope `name email`, `state` і PKCE.
3. Збережіть state/verifier у серверній сесії та перевірте state у callback.
4. Обміняйте код на Apple, використовуючи згенерований для провайдера
   client-secret JWT.
5. Перевірте підпис RS256 ID token через JWKS Apple та issuer, audience і строк
   дії.
6. Збережіть `(apple, sub)`. Для створення акаунта потрібні claims `email` і
   `email_verified`; Apple може повертати ім’я/email лише під час першої згоди.

Зберігайте приватний ключ Apple і client-secret JWT лише на сервері. Не
довіряйте імені/email, надісланим клієнтом.
