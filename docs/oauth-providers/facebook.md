# Facebook (Meta)

## English

**Protocol:** Facebook OAuth 2.0 authorization-code flow.

1. Configure a Meta app, HTTPS callback, and the `email` and `public_profile`
   permissions.
2. Redirect to the versioned Facebook dialog with state and PKCE; store both
   state and verifier server-side.
3. Exchange the code at the Graph API token endpoint and request `/me` with
   `id,email`.
4. Use the stable Graph `id` as the provider subject.
5. Meta's profile response is not treated as an email-verification assertion.
   It can sign in an identity previously linked to a local account; a new
   account requires an explicit identity link initiated by an authenticated
   local user.

The callback must not equate Facebook's general account verification with
verified email, nor link an existing account solely by matching email.

## Українська

**Протокол:** Facebook OAuth 2.0 authorization-code.

1. Налаштуйте Meta app, HTTPS callback і дозволи `email` та `public_profile`.
2. Перенаправте користувача на версійований Facebook dialog зі state та PKCE;
   зберігайте state і verifier на сервері.
3. Обміняйте код на Graph API token endpoint і запитайте `/me` з полями
   `id,email`.
4. Використовуйте стабільний Graph `id` як subject провайдера.
5. Відповідь Meta не вважається доказом підтвердження email. Вхід доступний для
   раніше прив’язаної ідентичності; нову можна прив’язати лише явною дією
   автентифікованого локального користувача.

Не прирівнюйте загальну верифікацію акаунта Facebook до підтвердженого email і
не прив’язуйте акаунти лише через збіг email.
