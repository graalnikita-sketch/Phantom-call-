# Протокол сервера, версия 1 (фаза 1)

Все тела запросов и ответов — JSON. Неизвестные поля отклоняются. Размер тела — до 8 КБ.

## Ключ и подпись

- Ключ устройства: ECDSA P-256. Публичный ключ передаётся как X.509 SubjectPublicKeyInfo в DER, закодированный стандартным base64. На Android это `publicKey.encoded`.
- Подпись: ECDSA с SHA-256 в формате ASN.1 DER, стандартный base64. На Android это алгоритм `SHA256withECDSA`.

## Подписываемые сообщения

Строки в UTF-8, `\n` — один байт перевода строки.

Регистрация:

```
PHANTOM-CALL/v1/register\n<nonce>\n<hex(SHA-256(SPKI DER)), строчные буквы>
```

Вход:

```
PHANTOM-CALL/v1/login\n<nonce>\n<device_id>
```

`<nonce>` — строка из ответа сервера, как получена, без перекодирования.

## Запросы

| Запрос | Вход | Тело | Ответ |
| --- | --- | --- | --- |
| `POST /v1/challenges` | нет | `purpose`: `register` или `login`; для `login` ещё `device_id` | 201: `challenge_id`, `nonce`, `expires_at` |
| `POST /v1/accounts` | нет | `challenge_id`, `public_key`, `signature` | 201: `phantom_id`, `device_id` |
| `POST /v1/sessions` | нет | `challenge_id`, `device_id`, `signature` | 201: `token`, `session_id`, `expires_at` |
| `GET /v1/me` | токен | — | 200: `phantom_id`, `device_id`, `sessions` |
| `DELETE /v1/me` | токен | — | 204; аккаунт, устройство и сессии удалены |
| `PUT /v1/me/push-token` | токен | `token` (пустая строка стирает) | 204 |
| `DELETE /v1/sessions/{id}` | токен | — | 204; `current` означает текущую сессию |
| `GET /v1/accounts/{phantom_id}/keys` | токен | — | 200: `phantom_id`, `devices[]` с `device_id` и `public_key` |
| `GET /healthz` | нет | — | 200 |

Токен передаётся в заголовке `Authorization: Bearer <token>`.

## Правила

- Запрос (challenge) живёт 60 секунд и одноразовый: он сгорает при первой попытке использования, даже неудачной.
- Запрос привязан к операции, а для входа — к `device_id`.
- Сессия живёт 30 дней; на устройство не больше пяти сессий, самая старая вытесняется.
- Один публичный ключ — один аккаунт.
- PHANTOM ID имеет вид `PH-XXXX-XXXX-XXXX` (60 случайных бит, алфавит Crockford Base32).

## Коды ошибок

`400 bad_json`, `400 bad_request`, `400 bad_public_key`, `401 invalid_challenge`, `401 bad_signature`, `401 invalid_credentials`, `401 unauthorized`, `404 not_found`, `409 key_already_registered`, `413 body_too_large`, `429 rate_limited`, `503 busy`.
