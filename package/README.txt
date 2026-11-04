X4 Shard {version} - общий мир для X4: Foundations

Нужно: X4: Foundations 9.00 в Steam (DLC не нужны), Windows 10/11.

УСТАНОВКА
- Vortex: кнопка «Mod Manager Download» на странице мода, Vortex поставит сам. Дальше шаг 3.
- Вручную:
  1. Steam -> X4: Foundations -> шестерёнка -> «Управление» -> «Просмотреть локальные файлы».
  2. Положи папку x4shard (в ней этот файл) в папку extensions игры (нет такой - создай).
     Должно получиться: ...\X4 Foundations\extensions\x4shard\content.xml
3. Запусти игру -> «Настройки» -> «Расширения» -> выключи Protected UI Mode (защищённый режим
   интерфейса) -> перезапусти игру. Без этого мод не выйдет в сеть.

ИГРА
- «Новая игра» -> в самом низу списка стартов «X4 Shard» -> начать.
- Бортовой компьютер предложит серверы - нажми цифру. Вход по Steam, вводить ничего не надо.
- Сервера нет в списке: скопируй его адрес (например 203.0.113.5:47110) и выбери «Connect by address».
- Сохранения не нужны: деньги и груз хранит сервер. Каждый раз - «Новая игра» -> «X4 Shard».
- Серверу уходят твой Steam ID, ник и где летает твой корабль. Пароль не нужен и не отправляется.

НЕ ПОДКЛЮЧАЕТСЯ
- «no network» - не выключен Protected UI Mode (шаг 3).
- «the network module did not load» - сетевой модуль x4shard\native\x4shardnet_64.dll не пустил
  антивирус или Smart App Control. Перед распаковкой: свойства архива -> «Разблокировать».
- Остальное: Steam -> X4 -> «Свойства» -> параметры запуска: -debug all -logfile debuglog.txt,
  запусти игру ещё раз и пришли файл Документы\Egosoft\X4\<число>\debuglog.txt.

Свой сервер - отдельный архив X4Shard-server.


X4 Shard {version} - a shared world for X4: Foundations

Needs X4: Foundations 9.00 on Steam (no DLC needed), Windows 10/11.

INSTALL
- Vortex: the "Mod Manager Download" button on the mod page, Vortex installs it. Then step 3.
- By hand:
  1. Steam -> X4: Foundations -> gear icon -> Manage -> Browse local files.
  2. Put the x4shard folder (the one with this file) into the game's extensions folder (create it if missing):
     ...\X4 Foundations\extensions\x4shard\content.xml
3. Start the game -> Settings -> Extensions -> turn Protected UI Mode off -> restart the game.
   Without it the mod cannot reach the network.

PLAY
- New Game -> "X4 Shard" at the bottom of the list of starts.
- The ship computer offers the servers - press the number. Login is by Steam, nothing to type.
- A server that is not listed: copy its address (e.g. 203.0.113.5:47110) and choose "Connect by address".
- No saves needed: the server keeps your money and cargo. Each time: New Game -> "X4 Shard".
- The server gets your Steam ID, your nickname and where your ship flies. No password is used or sent.

DOES NOT CONNECT
- "no network": Protected UI Mode is still on (step 3).
- "the network module did not load": antivirus or Smart App Control blocked
  x4shard\native\x4shardnet_64.dll. Before unpacking: archive Properties -> Unblock.
- Anything else: Steam -> X4 -> Properties -> launch options: -debug all -logfile debuglog.txt,
  start the game again and send Documents\Egosoft\X4\<number>\debuglog.txt.

Your own server: the separate X4Shard-server archive.
