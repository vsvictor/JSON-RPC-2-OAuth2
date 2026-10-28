# Twitch

## English

**Protocol:** Twitch OAuth 2.0 authorization-code flow.

1. Register a Twitch application with HTTPS redirect URI. Request
   `user:read:email`.
2. Start with state and PKCE and validate state on callback.
3. Exchange the code; query Helix `/users` with both the bearer token and the
   application's `Client-Id`.
4. Use the Helix user `id` as subject. Twitch does not provide a verified-email
   assertion in this integration, so new local accounts are not auto-provisioned.
5. An authenticated local user may explicitly link the Twitch subject; that
   linked identity can subsequently log in.

Email presence is not proof of email ownership.

## Українська

**Протокол:** Twitch OAuth 2.0 authorization-code.

1. Зареєструйте Twitch application з HTTPS redirect URI. Запитайте
   `user:read:email`.
2. Почніть зі state і PKCE та перевірте state у callback.
3. Обміняйте код; запитайте Helix `/users`, передавши bearer token і
   `Client-Id` застосунку.
4. Використовуйте Helix user `id` як subject. Ця інтеграція Twitch не має claim
   підтвердженого email, тому нові локальні акаунти автоматично не створюються.
5. Автентифікований локальний користувач може явно прив’язати Twitch subject;
   надалі прив’язана ідентичність зможе виконувати вхід.

Наявність email не доводить володіння адресою.
