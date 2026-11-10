X4 Shard {version} - свой сервер / your own server

Нужен Python 3.8+ (без сторонних пакетов) и открытый наружу TCP-порт 47110.
Needs Python 3.8+ (no extra packages) and TCP port 47110 open to the internet.

  python3 shard_server.py --name "Мой шард" --public-host <твой адрес>

- По умолчанию сервера нет ни в каком списке. При запуске он пишет ссылку x4shard://адрес:47110#отпечаток:
  её друзья вставляют в игре в «Connect by address...».
- --invite - закрытый сервер: новичков пускает только по ссылке-приглашению x4shard://адрес:47110/код#отпечаток.
- --register-to mc.idiot-home.ru:47110 - сервер появится в общем списке у всех (имя должно быть свободным).
- Соединение шифруется (TLS). Сертификат сервер делает сам при первом запуске: accounts.json.cert.pem и
  accounts.json.key.pem рядом со счетами. Храни их: с новым сертификатом игроки, которые у тебя уже были,
  к серверу не подключатся, пока не получат новую ссылку.
- Счета игроков - accounts.json рядом. Игроки входят по Steam ID и подписи, пароли не нужны.

- By default the server is not in any list. At start it prints its link x4shard://address:47110#fingerprint:
  your friends paste it into "Connect by address..." in the game.
- --invite makes it private: newcomers need the invite link x4shard://address:47110/code#fingerprint.
- --register-to mc.idiot-home.ru:47110 puts it into everyone's list (the name must be free).
- Connections are encrypted (TLS). The server makes its certificate on the first start: accounts.json.cert.pem
  and accounts.json.key.pem next to the accounts. Keep them: with a new certificate, players who were on your
  server before cannot connect until they get the new link.
- Player accounts are in accounts.json next to it. Players log in by Steam ID and a signature, no passwords.
