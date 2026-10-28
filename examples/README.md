# Examples

These examples are standalone binaries. They use the crate's default features
only when their required features are enabled; select a minimal feature set to
avoid compiling unrelated storage backends.

| Example | Demonstrates | Run |
| --- | --- | --- |
| `sqlite_jsonrpc` | SQLite storage, profile schema, RBAC, method registration and an in-process JSON-RPC request | `cargo run --example sqlite_jsonrpc --no-default-features --features sqlite` |
| `mongodb_auth` | MongoDB connection configuration, profile schema and user registration | `cargo run --example mongodb_auth --no-default-features --features mongodb` |
| `google_oauth` | Starting a Google authorization-code flow and completing its callback (manual CLI callback input) | `cargo run --example google_oauth --no-default-features --features sqlite,oauth-google` |

The [Kotlin Multiplatform client](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples/kotlin-multiplatform)
and [Flutter app](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples/flutter)
demonstrate calling the same registered methods from mobile clients.

Set `PASETO_LOCAL_KEY` to a PASERK-encoded `k4.local` key before running the
examples. The MongoDB example also accepts `MONGODB_HOST`, `MONGODB_DATABASE`,
`MONGODB_USER` and `MONGODB_PASSWORD`. The Google example needs `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and
`GOOGLE_REDIRECT_URI`. It asks you to paste the callback's code and state; use
the host application's HTTP route and session store instead of this CLI flow
in a deployed application.

Keep the returned state and PKCE verifier in a session bound to the initiating
browser; never accept the expected state or verifier from the callback request
itself. The example's in-memory SQLite database and manual CLI callback are for
local demonstration only.

## Приклади

Приклади є окремими виконуваними програмами. Щоб не збирати непотрібні
бекенди, вимикайте features за замовчуванням і вмикайте лише потрібні.

| Приклад | Демонстрація | Запуск |
| --- | --- | --- |
| `sqlite_jsonrpc` | SQLite, схема профілю, RBAC, реєстрація методів та JSON-RPC-запит у пам'яті | `cargo run --example sqlite_jsonrpc --no-default-features --features sqlite` |
| `mongodb_auth` | Налаштування з'єднання MongoDB, схема профілю та реєстрація користувача | `cargo run --example mongodb_auth --no-default-features --features mongodb` |
| `google_oauth` | Початок Google authorization-code flow та завершення callback (введення даних callback у CLI) | `cargo run --example google_oauth --no-default-features --features sqlite,oauth-google` |

[Kotlin Multiplatform-клієнт](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples/kotlin-multiplatform)
і [Flutter-застосунок](https://github.com/vsvictor/JSON-RPC-2-OAuth2/tree/master/examples/flutter)
показують виклик тих самих зареєстрованих методів із мобільних клієнтів.

Перед запуском задайте `PASETO_LOCAL_KEY` зі значенням PASERK-ключа `k4.local`.
Приклад MongoDB додатково підтримує змінні `MONGODB_HOST`,
`MONGODB_DATABASE`, `MONGODB_USER` і `MONGODB_PASSWORD`. Для Google потрібні `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` і
`GOOGLE_REDIRECT_URI`. Приклад попросить вставити `code` і `state` із callback;
у розгорнутому застосунку використовуйте HTTP-маршрут і сховище сесій.

Зберігайте отримані `state` і PKCE verifier у сесії, прив'язаній до браузера,
який ініціював вхід; ніколи не приймайте очікуваний state або verifier із
самого callback-запиту. SQLite у пам'яті та ручне введення callback у CLI
призначені лише для локальної демонстрації.
