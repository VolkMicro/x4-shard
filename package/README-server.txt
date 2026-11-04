X4 Shard {version} - свой сервер / your own server

Нужен Python 3.8+ (без сторонних пакетов) и открытый наружу TCP-порт 47110.
Needs Python 3.8+ (no extra packages) and TCP port 47110 open to the internet.

  python3 shard_server.py --host 0.0.0.0 --name "Мой шард" --public-host <твой адрес> --register-to mc.idiot-home.ru:47110

- Через полминуты сервер появится в списке у всех игроков. Имя должно быть свободным, а по --public-host
  должен отвечать сам сервер - иначе общий список его не возьмёт.
- Без --register-to в него заходят только по адресу (в игре: скопировать IP:порт -> «Connect by address»).
- Счета игроков - accounts.json рядом. Игроки входят по Steam ID и подписи, пароли не нужны.

- Half a minute later the server is in every player's list. The name must be free, and the server itself must
  answer at --public-host, or the shared list will not take it.
- Without --register-to it is joined by address only (in the game: copy IP:port -> "Connect by address").
- Player accounts are in accounts.json next to it. Players log in by Steam ID and a signature, no passwords.
