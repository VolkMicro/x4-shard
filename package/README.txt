X4 Shard {version} - общий мир для X4: Foundations

Нужно: X4: Foundations 9.00 в Steam (DLC не нужны), Windows 10/11.

УСТАНОВКА
- Vortex: кнопка «Mod Manager Download» на странице мода, Vortex поставит сам. Дальше шаг 3.
- Вручную:
  1. Steam -> X4: Foundations -> шестерёнка -> «Управление» -> «Просмотреть локальные файлы».
  2. Положи папку x4shard (в ней этот файл) в папку extensions игры (нет такой - создай).
     Должно получиться: ...\X4 Foundations\extensions\x4shard\content.xml
3. Запусти игру -> «Настройки» -> «Расширения» -> выключи Protected UI Mode (защищённый режим
   интерфейса) -> перезапусти игру. Без этого мод не выйдет в сеть. Пока он выключен, свой код могут
   грузить все установленные моды, не только этот: включай его обратно для модов, которым не доверяешь.

ИГРА
- «Новая игра» -> в самом низу списка стартов «X4 Shard» -> начать.
- Бортовой компьютер предложит серверы - нажми цифру. Вход по Steam, вводить ничего не надо.
- Сервера нет в списке или он закрытый: выбери «Connect by address...» и вставь (Ctrl+V) ссылку от его
  владельца (x4shard://203.0.113.5:47110/код#отпечаток) или просто адрес (203.0.113.5:47110).
- Сохранения не нужны: деньги и груз хранит сервер. Каждый раз - «Новая игра» -> «X4 Shard».
- Соединение шифруется (TLS). Серверу уходят твой Steam ID, ник и где летает твой корабль. Пароль не нужен.

НЕ ПОДКЛЮЧАЕТСЯ
- «no network» - не выключен Protected UI Mode (шаг 3).
- «the network module did not load» - Windows не дала загрузить x4shard\native\x4shardnet_64.dll
  (антивирус, Smart App Control). Не отключай защиту вслепую: исходник и SHA-256 модуля - на
  github.com/VolkMicro/x4-shard (сборка GitHub, воспроизводимая). Не уверен - не ставь мод.
- «showed another certificate» - у сервера другой сертификат, чем раньше или в ссылке. Если его владелец
  переустановил сервер, попроси у него новую ссылку. Иначе не подключайся: это может быть подмена.
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
   Without it the mod cannot reach the network. While it is off, every installed mod may load native code,
   not only this one: turn it back on for mods you do not trust.

PLAY
- New Game -> "X4 Shard" at the bottom of the list of starts.
- The ship computer offers the servers - press the number. Login is by Steam, nothing to type.
- A server that is not listed, or a private one: choose "Connect by address..." and paste (Ctrl+V) the link its
  owner gives (x4shard://203.0.113.5:47110/code#fingerprint) or just its address (203.0.113.5:47110).
- No saves needed: the server keeps your money and cargo. Each time: New Game -> "X4 Shard".
- The connection is encrypted (TLS). The server gets your Steam ID, your nickname and where your ship flies.
  No password is used.

DOES NOT CONNECT
- "no network": Protected UI Mode is still on (step 3).
- "the network module did not load": Windows did not let x4shard\native\x4shardnet_64.dll load (antivirus,
  Smart App Control). Do not just override it: the source and the module's SHA-256 are at
  github.com/VolkMicro/x4-shard (built by GitHub, reproducible). If unsure, do not use the mod.
- "showed another certificate": the server's certificate is not the one from before or from the link. If its
  owner reinstalled it, ask them for a new link. Otherwise do not connect: someone may be in between.
- Anything else: Steam -> X4 -> Properties -> launch options: -debug all -logfile debuglog.txt,
  start the game again and send Documents\Egosoft\X4\<number>\debuglog.txt.

Your own server: the separate X4Shard-server archive.
