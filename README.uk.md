# json-rpc-2-oauth2

[English version](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/README.md) ·
[Технічне завдання українською](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/task.md) ·
[Technical specification in English](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/task.en.md) ·
[Схеми потоків OAuth-провайдерів](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/README.md) ·
[Приклади використання](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/examples/README.md)

Автентифікація OAuth 2.0 за паролем, access/refresh-токени PASETO v4.local,
динамічні профілі користувачів і рольова авторизація для сервера `json-rpc-2`.

## Реалізації сховищ

Приклади клієнтської інтеграції для
[Kotlin Multiplatform](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples/kotlin-multiplatform)
і [Flutter](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples/flutter)
доступні в директорії прикладів.

Реалізовані бекенди сховищ: `MongoAuthServer`, `SqliteAuthServer`,
`SqlxAuthServer`, `RedisAuthServer`, `OracleAuthServer`, `MssqlAuthServer`,
`CassandraAuthServer` і `HbaseAuthServer`. `SqlxAuthServer` підтримує
PostgreSQL та MySQL через `SqlDatabase::{PostgreSql, MySql}`. Спільний контракт
`JsonRpcAuthServer` і реєстрація RPC-методів через `register_auth_methods`
однакові для всіх бекендів.

HBase використовує шлюз Thrift v1: `db_host` задається як `host:port` (порт за
замовчуванням — 9090), а `database_name` є префіксом для чотирьох таблиць
(`auth_{name}_users`, `_emails`, `_user_roles`, `_role_permissions`). Thrift v1
не підтримує автентифікацію, тому ім’я користувача й пароль БД відхиляються.
Унікальність email забезпечується атомарним резервуванням лічильника.

SQLite використовує `db_host` як шлях до файла (наприклад, `./auth.sqlite` або
`:memory:`); `database_name` використовується як резервний шлях. SQLite не має
окремих параметрів імені користувача/пароля, тому ініціалізація відхиляє ці
налаштування.

### PostgreSQL і MySQL

```rust,no_run
use json_rpc_2_oauth2::{JsonRpcAuthServer, SqlDatabase, SqlxAuthServer, TokenConfig};

async fn connect(key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = SqlxAuthServer::new(
        SqlDatabase::PostgreSql,
        key,
        TokenConfig::new("my-service"),
    )?;
    auth.set_db_host("db.example.test:5432");
    auth.set_db_name("my_service");
    auth.set_db_user("service_user");
    auth.set_db_password(std::env::var("DATABASE_PASSWORD")?.as_str());
    auth.initialize_storage().await?;
    Ok(())
}
```

Для MySQL виберіть `SqlDatabase::MySql` та задайте адресу, назву БД і облікові
дані. SQL-бекенди зберігають перевірені значення профілю як JSON у
`user_profiles.profile_json`; крейт перевіряє відповідність заданій схемі до
запису.

### Redis

```rust,no_run
use json_rpc_2_oauth2::{JsonRpcAuthServer, RedisAuthServer, TokenConfig};

async fn connect(key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = RedisAuthServer::new(key, TokenConfig::new("my-service"))?;
    auth.set_db_host("redis.example.test:6379");
    auth.set_db_name("0");
    auth.set_db_user("service_user");
    auth.set_db_password(std::env::var("REDIS_PASSWORD")?.as_str());
    auth.initialize_storage().await?;
    Ok(())
}
```

Для Redis `db_host` приймає адресу `host/port` або URL `redis://`/`rediss://`;
`database_name` задає номер логічної бази Redis (за замовчуванням — `0`).
Записи автентифікації використовують префікс ключів `auth:`. Надайте
налаштованому користувачеві Redis ACL-доступ до цього префікса.

### Oracle

```rust,no_run
use json_rpc_2_oauth2::{JsonRpcAuthServer, OracleAuthServer, TokenConfig};

async fn connect(key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = OracleAuthServer::new(key, TokenConfig::new("my-service"))?;
    auth.set_db_host("oracle.example.test:1521");
    auth.set_db_name("FREEPDB1");
    auth.set_db_user("service_user");
    auth.set_db_password(std::env::var("ORACLE_PASSWORD")?.as_str());
    auth.initialize_storage().await?;
    Ok(())
}
```

`db_host` для Oracle приймає адресу EZConnect із хостом і портом, за потреби —
із шляхом сервісу. Якщо шлях не задано, назва сервісу береться з
`database_name`. Бекенд використовує таблиці Oracle для користувачів і
нормалізованих зв’язків RBAC, а JSON профілю зберігає у CLOB.

### Microsoft SQL Server

```rust,no_run
use json_rpc_2_oauth2::{JsonRpcAuthServer, MssqlAuthServer, TokenConfig};

async fn connect(key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = MssqlAuthServer::new(key, TokenConfig::new("my-service"))?;
    auth.set_db_host("sqlserver.example.test:1433");
    auth.set_db_name("auth_service");
    auth.set_db_user("service_user");
    auth.set_db_password(std::env::var("MSSQL_PASSWORD")?.as_str());
    auth.initialize_storage().await?;
    Ok(())
}
```

Налаштована база SQL Server має вже існувати та бути доступною для логіна.
Бекенд створює таблиці у схемі `dbo` і зберігає перевірені значення профілю як
JSON у `user_profiles.profile_json`. Перевірка сертифіката сервера ввімкнена за
замовчуванням; `set_trust_server_certificate(true)` доречний лише для локальної
розробки або тестових серверів із самопідписаним сертифікатом.

### Cassandra

```rust,no_run
use json_rpc_2_oauth2::{CassandraAuthServer, JsonRpcAuthServer, TokenConfig};

async fn connect(key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = CassandraAuthServer::new(key, TokenConfig::new("my-service"))?;
    auth.set_db_host("cassandra.example.test:9042");
    auth.set_db_name("auth_service");
    auth.set_db_user("service_user");
    auth.set_db_password(std::env::var("CASSANDRA_PASSWORD")?.as_str());
    auth.initialize_storage().await?;
    Ok(())
}
```

Бекенд Cassandra використовує `database_name` як CQL keyspace. Якщо keyspace не
існує, ініціалізація створює його з `SimpleStrategy` і коефіцієнтом реплікації
`1` для розробки або однонодового середовища; для production-кластерів слід
заздалегідь створити keyspace з відповідною стратегією реплікації. Адаптер
використовує Rust-драйвер Scylla, сумісний із протоколом Cassandra. За
замовчуванням драйвер підключається до адрес, які оголошують вузли. Для
однонодового розгортання за NAT або TCP-проксі можна викликати
`set_translate_peers_to_contact_point(true)`, щоб спрямовувати знайдені адреси
вузлів через налаштовану адресу підключення. Не вмикайте це для багатовузлового
кластера, якщо ця адреса не є його проксі.

## Налаштування та реєстрація методів

```rust,no_run
use json_rpc_2_oauth2::{
    JsonRpcAuthServer, MongoAuthServer, ProfileFieldType, TokenConfig,
};
use json_rpc_2_server::RpcServer;
use std::collections::HashMap;

async fn configure(paserk_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = MongoAuthServer::new(paserk_key, TokenConfig::new("my-service"))?;
    auth.set_db_host("mongodb://localhost:27017");
    auth.set_db_name("my_service");
    auth.set_db_user("service_user");
    auth.set_db_password(std::env::var("MONGODB_PASSWORD")?.as_str());
    auth.set_profile_schema(HashMap::from([
        ("display_name".to_owned(), ProfileFieldType::Text),
        ("joined_at".to_owned(), ProfileFieldType::DateTime),
        ("avatar".to_owned(), ProfileFieldType::Blob),
    ]))?;
    auth.initialize_storage().await?;

    let rpc = RpcServer::new();
    auth.register_auth_methods(&rpc)?;
    Ok(())
}
```

Ключ має бути у форматі PASERK `k4.local`. Його можна згенерувати через
`pasetors::keys::SymmetricKey::<pasetors::version4::V4>::generate()` і зберігати
у менеджері секретів. Усі екземпляри, які перевіряють ці токени, мають
використовувати той самий ключ.

## Вибір Cargo features

Крейт є необов’язковою залежністю застосунку, який запускає сервер
`JSON-RPC-2`; це не feature самого `json-rpc-2-server`, оскільки OAuth2-крейт
залежить від серверного крейту. Додайте GitHub-залежність і передавайте
features із застосунку:

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

За замовчуванням вмикаються всі сховища й провайдери. Для мінімальної збірки
задайте `default-features = false` і виберіть `mongodb`, `sqlite`, `sqlx`
(PostgreSQL/MySQL), `redis`, `oracle`, `mssql`, `cassandra`, `hbase` та
необхідні features провайдерів, наприклад `oauth-google`, `oauth-github` або
`oauth-firebase-authentication`. `all-storages`, `all-oauth-providers` і
`oauth2` є агрегувальними features. Виклик провайдера з вимкненим feature
повертає помилку конфігурації. PostgreSQL і MySQL використовують спільний
SQLx-адаптер; `postgres` і `mysql` є aliases для `sqlx`.

Застосунок налаштовує та ініціалізує вибране сховище, а потім викликає
`register_auth_methods` із власним `RpcServer`. HTTP redirect/callback
маршрути OAuth належать застосунку.

## OAuth2-провайдери ідентичності

`JsonRpcAuthServer` надає методи `provider_authorization` та
`handle_provider_callback` для OAuth2-потоків authorization code. Підтримуються
Google, Apple, Microsoft, Facebook, X, LinkedIn, Slack, GitHub, GitLab,
Bitbucket, Discord, Twitch, Spotify, Auth0 та Okta. Для Microsoft, GitLab,
Auth0 і Okta потрібен довірений OIDC issuer URL; issuer Microsoft має
використовувати `login.microsoftonline.com`. ID-токени Apple перевіряються за
підписом через JWKS Apple та валідуються за issuer і audience.

Для Firebase Authentication призначений окремий метод
`handle_firebase_id_token(project_id, id_token)`, оскільки клієнти Firebase
отримують ID-токени через Firebase SDK, а не через redirect authorization-code
цього крейту. Сервер перевіряє підпис, issuer, audience і строк дії токена.

Новий локальний акаунт створюється лише якщо провайдер повертає email із
підтвердженням. Раніше прив’язана ідентичність може виконувати вхід і без
підтвердженого email, але збіг email ніколи не прив’язує акаунти автоматично.
Використовуйте `handle_provider_link` або `link_firebase_id_token` лише після
того, як застосунок автентифікував локального користувача, до якого
прив’язуватиметься ідентичність. Зберігайте OAuth client secrets, callback state
і PKCE verifiers на сервері; не довіряйте `expected_state`, отриманому з
браузера. Облікові дані провайдера не передаються через JSON-RPC методи.
Дивіться [двомовні схеми потоків провайдерів](https://github.com/vsvictor/JSON-RPC-2-OAuth2/blob/master/docs/oauth-providers/README.md).

```rust,no_run
use json_rpc_2_oauth2::{
    AuthError, JsonRpcAuthServer, OAuth2Provider, ProviderAuthorizationRequest,
    ProviderCallbackRequest,
};

async fn provider_login(
    auth: &impl JsonRpcAuthServer<StorageError = AuthError>,
    client_id: String,
    client_secret: String,
    callback_uri: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = auth.provider_authorization(ProviderAuthorizationRequest {
        provider: OAuth2Provider::Google,
        client_id: client_id.clone(),
        redirect_uri: callback_uri.clone(),
        scopes: Vec::new(),
        issuer_url: None,
    }).await?;

    // Перенаправте користувача на flow.authorization_url. Збережіть state
    // і PKCE verifier у серверній сесії, прив'язаній до браузера.
    let _tokens = auth.handle_provider_callback(ProviderCallbackRequest {
        provider: OAuth2Provider::Google,
        client_id,
        client_secret,
        redirect_uri: callback_uri,
        code: "authorization-code-from-callback".to_owned(),
        state: flow.state.clone(),
        expected_state: flow.state,
        pkce_verifier: flow.pkce_verifier,
        issuer_url: None,
    }).await?;
    Ok(())
}
```

У реальному callback отримуйте `state` і `code` з відповіді провайдера та
порівнюйте `state` зі значенням, збереженим у серверній сесії; не приймайте
`expected_state` з параметрів callback. Зберігайте PKCE verifier і client secret
на сервері. Для Apple `client_secret` має бути підписаним JWT, згенерованим для
провайдера. Цей приклад демонструє API; у production callback відновлюйте
state та PKCE-дані із серверної сесії й не використовуйте state повторно між
браузерними сесіями.

## RPC-методи

- `auth.register`: приймає `email`, `password` і необов'язковий `profile` зі
  значеннями-рядками.
- `auth.login`: приймає `email`, `password` і `grant_type: "password"`.
- `auth.refresh`: приймає `refresh_token`.
- `auth.updateProfile`: приймає `profile` і bearer-токен.
- `rbac.addRoleToUser` / `rbac.removeRoleFromUser`: вимагають
  `rbac.users.write`.
- `rbac.addPermissionToRole` / `rbac.removePermissionFromRole`: вимагають
  `rbac.roles.write`.

Поки upstream JSON-RPC transport не передає заголовки авторизації через
`TransportContext`, захищені RPC-методи приймають `access_token` або
`authorization: "******"` у параметрах. Застосунки, що отримують bearer-заголовки
на транспортному рівні, можуть використовувати `authenticate_access_token` або
`require_permission` у власному middleware. Першу адміністративну роль і
дозволи потрібно створити поза цим потоком.

Динамічні значення профілю передаються як рядки та перевіряються/перетворюються
відповідно до `ProfileFieldType`: текст, знакове 64-бітове ціле число, скінченне
число з плаваючою комою, логічне значення, дата й час RFC 3339 або бінарні дані
у стандартному Base64. Назви полів профілю мають бути ASCII-ідентифікаторами,
щоб запобігти ін'єкціям у dotted path/operator MongoDB.
