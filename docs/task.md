# Технічне завдання: `json-rpc-2-oauth2`

[English version](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/task.en.md)

Цей документ описує реалізований контракт автентифікації, авторизації,
профілювання, сховищ, OAuth2-провайдерів і Cargo features для крейту
[`json-rpc-2-oauth2`](https://github.com/vsvictor/JSON-RPC-2-OAuth2), який
інтегрується із сервером Rust
[`JSON-RPC-2`](https://github.com/vsvictor/JSON-RPC-2).

## 1. Інтеграція та правила залежностей

Крейт є необов’язковою залежністю застосунку, а не feature або зворотною
залежністю `json-rpc-2-server`. Сам OAuth2-крейт залежить від серверного
крейту, тому додавання його назад до того самого крейту створить циклічну
Cargo-залежність. Застосунок може зробити інтеграцію опційною, задавши GitHub
залежність і передаючи Cargo features:

```toml
[dependencies]
json-rpc-2-oauth2 = { git = "https://github.com/vsvictor/JSON-RPC-2-OAuth2", default-features = false, optional = true }

[features]
auth-google-sqlite = [
    "dep:json-rpc-2-oauth2",
    "json-rpc-2-oauth2/sqlite",
    "json-rpc-2-oauth2/oauth-google",
]
```

Локальні залежності через `path` заборонені. У
[`Cargo.toml`](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/Cargo.toml)
залежність від JSON-RPC-2 задається GitHub-репозиторієм і зафіксованою
ревізією. RPC-обробники автентифікації, профілю та RBAC реєструються на
застосунку `RpcServer` методом `register_auth_methods`.

Типові features зберігають повну сумісність із наявною збіркою:

| Feature | Призначення |
|---|---|
| `all-storages` | Вмикає адаптери MongoDB, SQLite, SQLx (PostgreSQL/MySQL/SQLite), Redis, Oracle, MS SQL Server, Cassandra та HBase. |
| `all-oauth-providers` / `oauth2` | Вмикає всіх підтримуваних OAuth/OIDC-провайдерів і перевірку Firebase ID token. |
| `mongodb`, `sqlite`, `sqlx`, `redis`, `oracle`, `mssql`, `cassandra`, `hbase` | Вмикає відповідні реалізації сховищ. `postgres` і `mysql` є aliases для `sqlx`. |
| `oauth-google`, `oauth-firebase-authentication`, `oauth-apple`, `oauth-microsoft`, `oauth-facebook`, `oauth-x`, `oauth-linkedin`, `oauth-slack`, `oauth-github`, `oauth-gitlab`, `oauth-bitbucket`, `oauth-discord`, `oauth-twitch`, `oauth-spotify`, `oauth-auth0`, `oauth-okta` | Вмикає зазначеного провайдера. Виклик вимкненого провайдера повертає явну помилку конфігурації. |

Для мінімальної збірки задавайте `default-features = false` і вибирайте тільки
потрібні features сховища та провайдера. Адаптер SQLx спільний для PostgreSQL
і MySQL; окремий адаптер SQLite використовує SQLite driver SQLx.

## 2. Автентифікація та авторизація

Публічний контракт сервера — `JsonRpcAuthServer`. Він охоплює конфігурацію
підключення до БД (`set_db_host`, `set_db_name`, `set_db_user`,
`set_db_password`), ініціалізацію сховища, налаштування схеми профілю,
реєстрацію/вхід за паролем, оновлення токенів, вхід і прив’язування зовнішніх
ідентичностей та операції RBAC. Доступні адаптери:
`MongoAuthServer`, `SqliteAuthServer`, `SqlxAuthServer`, `RedisAuthServer`,
`OracleAuthServer`, `MssqlAuthServer`, `CassandraAuthServer` і `HbaseAuthServer`.

Access і refresh tokens використовують PASETO v4.local. `TokenConfig` задає
issuer та строки дії (типово access token — 15 хвилин, refresh token — 30
днів). Екземпляри сервісу, що перевіряють однакові токени, мають спільно
використовувати PASERK-ключ `k4.local`. Claims access token включають issuer,
subject, строк дії, ролі, дозволи та призначення токена; access і refresh
tokens не взаємозамінні. Паролі зберігаються із застосуванням Argon2.

`register_auth_methods` реєструє RPC-методи застосунку:

- `auth.register`, `auth.login`, `auth.refresh`, `auth.updateProfile`.
- `rbac.addRoleToUser` / `rbac.removeRoleFromUser`, потрібен дозвіл
  `rbac.users.write`.
- `rbac.addPermissionToRole` / `rbac.removePermissionFromRole`, потрібен
  дозвіл `rbac.roles.write`.

OAuth API бібліотеки не реєструють browser redirect RPC-методи. HTTP
redirect/callback-маршрути та браузерний стан сесії належать host-застосунку.
Поки upstream transport не передає заголовки авторизації через request
context, захищені RPC-обробники приймають `access_token` або `authorization` у
параметрах. Альтернативно застосунок може викликати
`authenticate_access_token` і `require_permission` у middleware.

## 3. Динамічні профілі користувачів

Застосунок визначає поля профілю програмно як map назв полів до
`ProfileFieldType`: `Text`, `Integer` (знакове 64-бітове), `Float` (скінченне),
`Boolean`, `DateTime` (RFC 3339) і `Blob` (у JSON-RPC передається як стандартний
Base64). Значення перевіряються до запису. Невідомі поля, неправильні
значення та небезпечні назви полів відхиляються. Абстрактні типи мають
узгоджені представлення в PostgreSQL, MySQL, Oracle, MS SQL Server, SQLite,
MongoDB, Redis, Cassandra та HBase.

## 4. Адаптери сховищ

| Адаптер | Конфігурація та особливості |
|---|---|
| MongoDB | `db_host` приймає MongoDB URI; користувачі, профілі, ролі, дозволи та зовнішні ідентичності зберігаються в колекціях із необхідними обмеженнями унікальності. |
| SQLite | `db_host` є шляхом до файла або SQLite URI; `database_name` — резервний шлях. Окремі ім’я користувача/пароль БД відхиляються. |
| PostgreSQL / MySQL | `SqlxAuthServer` використовує `SqlDatabase::{PostgreSql, MySql}`. Перевірені профілі SQL зберігаються як JSON. |
| Redis | `db_host` приймає host/port або `redis://` / `rediss://`; `database_name` обирає логічну БД. Записи мають префікс `auth:`. |
| Oracle | `db_host` приймає EZConnect host/port і, за потреби, service path; JSON профілю зберігається у CLOB. |
| MS SQL Server | Цільова БД має існувати; за замовчуванням увімкнено перевірку сертифіката сервера. |
| Cassandra | `database_name` є CQL keyspace. Відсутній keyspace створюється для розробки з `SimpleStrategy` і replication factor 1; для production слід заздалегідь налаштувати відповідну стратегію реплікації. |
| HBase | Використовує Thrift v1 gateway з `host:port` (типовий порт 9090). Thrift v1 не має автентифікації, тому ім’я користувача/пароль БД відхиляються. |

Усі реалізовані адаптери зберігають зовнішні ідентичності за унікальною парою
`(provider, subject)`.

## 5. OAuth2 та зовнішні ідентичності

Authorization-code потік доступний через `provider_authorization` і
`handle_provider_callback`. Бібліотека створює URL авторизації з випадковим
`state` і PKCE S256 challenge, обмінює код, отримує дані зовнішньої
ідентичності та повертає локальні PASETO-токени. Host-застосунок повинен
зберігати state і PKCE verifier у серверній сесії та відновлювати їх у
callback; не довіряйте переданому callback параметру `expected_state` і не
передавайте client secrets/verifiers браузеру.

Authorization-code / OIDC провайдери: Google, Apple, Microsoft, Facebook
(Meta), X, LinkedIn, Slack, GitHub, GitLab, Bitbucket, Discord, Twitch,
Spotify, Auth0 та Okta. Для Microsoft, GitLab, Auth0 та Okta потрібен довірений
OIDC issuer URL. Issuer Microsoft має використовувати
`login.microsoftonline.com`. OIDC discovery перевіряє issuer та origins
endpoints; для Microsoft userinfo дозволений Microsoft Graph. ID-токени Apple
перевіряються за JWKS Apple, issuer, audience і строком дії.

Firebase Authentication має окремий потік `handle_firebase_id_token`. Клієнт
отримує Firebase ID token через Firebase Authentication SDK; сервер перевіряє
підпис RS256 за Secure Token JWKS та claims issuer, audience, subject і строк
дії відповідно до налаштованого project ID. Firebase не використовує
authorization-code redirect у цьому API.

Правила зовнішніх акаунтів:

1. Раніше прив’язана пара `(provider, subject)` може входити без email.
2. Новий локальний акаунт може бути створений лише за email, який провайдер
   явно позначив як підтверджений.
3. Збіг із наявним локальним email не прив’язує та не об’єднує акаунти;
   повертається `AccountLinkRequired`.
4. Прив’язування провайдера виконується тільки після автентифікації наявного
   локального користувача самим застосунком. `handle_provider_link` і
   `link_firebase_id_token` не автентифікують цього користувача самостійно.
5. OAuth-токени та credentials провайдера не використовуються як локальні
   access tokens сервісу.

Дивіться [двомовний індекс схем потоків](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/README.md)
та окремі інструкції:
[Google](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/google.md),
[Firebase Authentication](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/firebase-authentication.md),
[Apple](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/apple.md),
[Microsoft](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/microsoft.md),
[Facebook](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/facebook.md),
[X](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/x.md),
[LinkedIn](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/linkedin.md),
[Slack](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/slack.md),
[GitHub](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/github.md),
[GitLab](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/gitlab.md),
[Bitbucket](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/bitbucket.md),
[Discord](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/discord.md),
[Twitch](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/twitch.md),
[Spotify](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/spotify.md),
[Auth0](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/auth0.md)
та [Okta](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/okta.md).

## 6. Критерії приймання та перевірки

- Крейт збирається з типовими features і з мінімальним обраним набором через
  `default-features = false`.
- Вимкнений адаптер або провайдер не потребує його optional runtime-залежностей
  і не експортується як доступна реалізація/API.
- Перевіряються операції парольної автентифікації, токенів, профілів, RBAC і
  зовнішніх ідентичностей.
- У [`examples/`](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples)
  є двомовний каталог і приклади SQLite/RPC, MongoDB та Google OAuth2, що
  збираються з потрібними мінімальними Cargo features.
- Додаткові приклади клієнтів демонструють виклики JSON-RPC з
  [Kotlin Multiplatform](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples/kotlin-multiplatform)
  і [Flutter](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples/flutter);
  Flutter керує станом через BLoC і зберігає токени у захищеному сховищі.
- Інтеграційні тести виконують операції з адаптерами до тестових контейнерів,
  якщо середовище це підтримує.
- Перевірка OAuth callback на реальних акаунтах провайдерів залежить від
  конфігурації розгортання і не випливає автоматично з unit-тестів чи тестів
  сховищ.
- Помилки валідації та авторизації перетворюються на JSON-RPC помилки;
  помилки БД, криптографії чи серіалізації не маскуються успішними
  результатами.

Репозиторії: [OAuth2-крейт на GitHub](https://github.com/vsvictor/JSON-RPC-2-OAuth2) ·
[JSON-RPC-2 на GitHub](https://github.com/vsvictor/JSON-RPC-2).
