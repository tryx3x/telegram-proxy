<img src="docs/banner.png" alt="Telegram Proxy Collector" width="100%">

# Telegram Proxy Collector

Собирает MTProto и SOCKS5 прокси из открытых источников и **проверяет их
настоящим хендшейком протокола**, а не открытым TCP-портом. В списки попадает
только то, к чему Telegram действительно подключится.

## Чем эта проверка отличается от обычной

Большинство подобных парсеров делают `socket.connect()` и считают порт
открытым равным «прокси рабочий». На порт 443 отвечает любой веб-сервер,
поэтому такие списки на 60-90 процентов состоят из мусора.

Здесь для каждого типа выполняется полноценный обмен:

| Тип прокси | Что делает проверка | Метка в результате |
|---|---|---|
| MTProto fake-TLS (`ee…`) | Отправляет ClientHello с HMAC-SHA256 по секрету. Ответ сервера содержит digest, который проверяется криптографически. Подделать его, не зная секрета, нельзя. | `faketls_hmac` |
| MTProto obfuscated2 (`dd…` и обычные) | Отправляет 64-байтовый init-пакет и настоящий `req_pq_multi`. Прокси обязан передать его в Telegram и вернуть `resPQ`. | `mtproto_respq`, `mtproto_reply` |
| SOCKS5 | Приветствие, при наличии логина авторизация по RFC 1929, затем `CONNECT` на адрес дата-центра Telegram. | `socks5_connect` |

Побочный эффект: поле `probe_resistant` наконец означает что-то настоящее.
Оно выставляется для fake-TLS прокси, подтвердивших HMAC, то есть тех, кто
для постороннего наблюдателя выглядит обычным HTTPS к домену-маске.

---

## Списки

Обновляются автоматически каждые 2 часа.

| Файл | Что внутри |
|---|---|
| [proxy_ru.txt](https://raw.githubusercontent.com/tryx3x/telegram-proxy/main/lists/proxy_ru.txt) | MTProto с маскировкой под российские сервисы: Yandex, VK, Mail.ru, Gosuslugi, Sber |
| [proxy_eu.txt](https://raw.githubusercontent.com/tryx3x/telegram-proxy/main/lists/proxy_eu.txt) | MTProto, Европа и всё остальное |
| [proxy_us.txt](https://raw.githubusercontent.com/tryx3x/telegram-proxy/main/lists/proxy_us.txt) | MTProto, США и Канада |
| [proxy_asia.txt](https://raw.githubusercontent.com/tryx3x/telegram-proxy/main/lists/proxy_asia.txt) | MTProto, Азиатско-Тихоокеанский регион |
| [mtproto.txt](https://raw.githubusercontent.com/tryx3x/telegram-proxy/main/lists/mtproto.txt) | Все MTProto вместе |
| [socks5.txt](https://raw.githubusercontent.com/tryx3x/telegram-proxy/main/lists/socks5.txt) | SOCKS5 |
| [all.txt](https://raw.githubusercontent.com/tryx3x/telegram-proxy/main/lists/all.txt) | Всё сразу |
| [tme_links.txt](https://raw.githubusercontent.com/tryx3x/telegram-proxy/main/lists/tme_links.txt) | То же в виде ссылок `https://t.me/proxy?…`, удобно пересылать в чат |
| [proxies.json](https://raw.githubusercontent.com/tryx3x/telegram-proxy/main/lists/proxies.json) | Полные данные: пинг, страна, домен-маска, метод подтверждения |
| [stats.json](https://raw.githubusercontent.com/tryx3x/telegram-proxy/main/lists/stats.json) | Статистика последнего прогона |

Сортировка внутри файлов: сначала probe-resistant MTProto, затем остальной
MTProto, затем SOCKS5. Внутри каждой группы по возрастанию пинга.

### С телефона

Страница со всеми прокси и кнопками подключения:
**https://tryx3x.github.io/telegram-proxy/**

Она читает `lists/proxies.json` и показывает пинг, страну, домен-маску и то,
чем именно подтверждён каждый прокси.

---

## Как работает прогон

1. **Сбор.** Параллельно качаются источники из [sources.txt](sources.txt):
   32 списка MTProto и 9 списков SOCKS5. Разбираются форматы `tg://proxy`,
   `t.me/proxy`, `host:port:secret`, `socks5://user:pass@host:port`, JSON и
   Clash-YAML.
2. **Отсев до сети.** Мусорные порты для MTProto, слишком короткие секреты и
   маскировка под заведомо заблокированные ресурсы отбрасываются сразу.
3. **Кэш.** Кэш неудач нужен только для SOCKS5: их около 180 000 и за один
   прогон столько не проверить. Провалившийся SOCKS5 не трогается
   `--seen-ttl` часов. MTProto проверяется каждый раз целиком, как и
   победители прошлого прогона: публикуется только подтверждённое сейчас,
   поэтому один неудачный прогон не должен обнулять список.
4. **Лимит объёма.** MTProto-кандидатов на два порядка меньше, чем SOCKS5
   (около 1900 против 180 000), поэтому `--max-check` урезает только хвост
   SOCKS5, а MTProto проверяется целиком.
5. **Этап 1, TCP.** Быстрый коннект в несколько сотен потоков. Заодно даёт реальный IP,
   по которому работает GeoIP-фильтр (в прошлой версии он молча пропускал все
   доменные прокси).
6. **Этап 2, хендшейк.** Полная проверка протокола из таблицы выше.
7. **Запись.** Списки, JSON и статистика в `lists/`.

---

## Локальный запуск

```bash
pip install -r requirements.txt
```

```bash
curl -fsSL -o data/GeoLite2-Country.mmdb https://raw.githubusercontent.com/Dreamacro/maxmind-geoip/release/Country.mmdb
```

```bash
python -m collector --geoip data/GeoLite2-Country.mmdb
```

GeoIP не обязателен: без него проверка идёт, но фильтр по странам выключается.

### Параметры

| Флаг | По умолчанию | Что делает |
|---|---|---|
| `--sources` | `sources.txt` | Файл со списком источников |
| `--output-dir` | `lists` | Куда писать результат |
| `--geoip` | нет | Путь к базе MaxMind `.mmdb` |
| `--top` | `0` | Сколько прокси оставить в каждом файле, 0 значит все |
| `--max-check` | `40000` | Максимум прокси за прогон |
| `--tcp-timeout` | `2.0` | Таймаут первого этапа |
| `--timeout` | `5.0` | Таймаут хендшейка |
| `--workers` | `150` | Потоков на этапе TCP |
| `--probe-workers` | `80` | Потоков на этапе хендшейка |
| `--no-connect-test` | выкл | Для SOCKS5 не проверять `CONNECT` до Telegram |
| `--cooldown` | `5.0` | Пауза между этапами, чтобы ОС освободила сокеты |
| `--seen-file` | `data/seen.json` | Кэш неудачных SOCKS5 |
| `--seen-ttl` | `6` | TTL кэша в часах |
| `--quiet` | выкл | Не печатать каждый источник |

### Если проверка вдруг даёт ноль рабочих

На Windows при больших `--workers` система упирается в лимит эфемерных портов
и буферов сокетов: в логе появляются `WinError 10055` и `WinError 10048`.
Сборщик распознаёт такие ошибки, повторяет попытку и не заносит эти прокси в
кэш неудач, но если их много, уменьшите `--probe-workers` и `--workers`.
Дефолты подобраны под обычную рабочую машину, а в CI на Linux воркфлоу
поднимает их до 400 и 200.

### Тесты

```bash
python -m unittest discover -s tests -v
```

---

## Структура

```
collector/          пакет сборщика
  cli.py            разбор аргументов и оркестрация этапов
  sources.py        чтение sources.txt и параллельное скачивание
  parse.py          разбор форматов, декодирование fake-TLS секрета
  probe.py          хендшейки MTProto fake-TLS, obfuscated2, SOCKS5
  geoip.py          база MaxMind
  cache.py          кэш проверенных с честным TTL
  output.py         запись списков и статистики
  model.py          модель прокси, регионы, страны, порты
sources.txt         редактируемый список источников
index.html          страница для телефона, читает lists/proxies.json
lists/              результат прогона
tests/              юнит-тесты
```

---

## Настройка своего репозитория

1. Создайте пустой репозиторий и запушьте туда содержимое этой папки.
2. Settings → Actions → General → Workflow permissions → **Read and write
   permissions**, иначе воркфлоу не сможет коммитить списки.
3. Settings → Pages → Source: **Deploy from a branch**, ветка `main`, папка
   `/ (root)`. Страница поднимется по адресу из раздела выше.
4. Actions → «Обновление списков прокси» → **Run workflow** для первого
   прогона, дальше он идёт по расписанию каждые 2 часа.

Кэш проверенных прокси живёт в `actions/cache`, а не в коммитах, поэтому
история репозитория не засоряется.

---

## Безопасность

Бесплатный прокси видит, куда и в каком объёме идёт ваш трафик, и может его
записывать. MTProto шифрует содержимое переписки, но владелец прокси знает
ваш IP и время сессий. Это инструмент обхода блокировки, а не анонимности и
не замена VPN. Не используйте бесплатные прокси там, где важна приватность:
для банков, рабочих аккаунтов и всего, что жалко потерять.

Все прокси берутся из открытых источников и предоставляются как есть.
