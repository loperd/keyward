# keyward for Chromium — privacy policy

_Last updated: 29 September 2026_

The keyward browser extension lets websites use the passkeys kept in your
keyward vault, and save new ones there. It is a companion to the keyward app for
macOS and does nothing without it.

## What the extension handles

When a website asks the browser for a passkey (`navigator.credentials.get`) or
wants to create one (`navigator.credentials.create`), the extension passes the
request's own parameters to the keyward app on your Mac:

- the address (origin) of the page, as the browser reports it;
- the site's name and relying-party identifier;
- the challenge and the identifiers of passkeys the site allows or excludes;
- when a passkey is created, the account name and display name the site sends.

The keyward app answers with a signature (to sign in) or a new public key (to
register). The private key never leaves the app. The extension shows the names
of the matching vault items and accounts in its own window, so that you can
choose one.

## Where it goes

Only to the keyward app on the same computer, over the browser's native
messaging channel. That channel is encrypted end to end between the extension
and the app (an ephemeral key exchange and AES-256-GCM for every connection).

The extension sends **nothing** to the developer, to keyward's servers or to any
third party. It has no analytics, no telemetry, no advertising and no remote
code. It does not read, store or transmit page content, browsing history,
passwords, form data or anything else a page shows.

## What it keeps

While a request is open, its parameters and the names shown in the chooser are
held in the browser's session storage, which lives in memory only and is
cleared when the request ends or the browser closes. Nothing is written to disk
by the extension.

Your passkeys are stored by the keyward app in your own Bitwarden-compatible
vault, encrypted, as described in the app's documentation.

## Your control

Every sign-in and every new passkey needs Touch ID in the keyward app; the
prompt names the site and the account. You can always choose "Another way" to
let the browser handle the request itself, and you can remove the extension at
any time.

## Contact

Questions: open an issue at https://github.com/loperd/keyward/issues.

---

# keyward для Chromium — политика конфиденциальности

_Обновлено: 29 сентября 2026_

Расширение keyward позволяет сайтам пользоваться passkey из твоего волта keyward
и сохранять туда новые. Оно работает только вместе с приложением keyward для
macOS и без него ничего не делает.

**Что передаётся.** Когда сайт просит passkey или хочет создать новый,
расширение передаёт приложению keyward на этом же компьютере параметры самого
запроса: адрес страницы (как его сообщает браузер), имя сайта и его
идентификатор, challenge, идентификаторы разрешённых или исключённых passkey, а
при создании — имя аккаунта, которое прислал сайт. Приложение отвечает подписью
или новым публичным ключом. Приватный ключ никогда не покидает приложение.

**Куда.** Только в приложение keyward на этом же компьютере, по каналу native
messaging браузера, зашифрованному от расширения до приложения. Разработчику,
серверам keyward и третьим лицам не передаётся **ничего**: нет аналитики,
телеметрии, рекламы и удалённого кода. Содержимое страниц, история, пароли и
данные форм не читаются и не передаются.

**Что хранится.** Пока запрос открыт, его параметры и имена в окне выбора лежат
в сессионном хранилище браузера — только в памяти — и стираются, когда запрос
завершён или браузер закрыт. На диск расширение ничего не пишет.

**Контроль.** Каждый вход и каждый новый passkey требуют Touch ID в приложении
keyward, в запросе названы сайт и аккаунт. Всегда можно выбрать «Другим
способом» и отдать запрос браузеру, а расширение — удалить.

Вопросы: https://github.com/loperd/keyward/issues.
