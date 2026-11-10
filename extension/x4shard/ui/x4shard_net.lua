-- X4 Shard client bridge.
-- Talks to shard servers over TLS, one text line per message (protocol in server/shard_server.py), through
-- native/x4shardnet_64.dll: X4's Lua has no sockets, but with Protected UI Mode off package.loadlib can load a Lua
-- C module. The module is loaded only when the X4 Shard start is played: its MD (md/x4shard_client.xml) drives
-- this file every frame with the event "x4shard.tick", and in any other game nothing of it runs.
-- A shard has its own certificate; the game talks to it only if the certificate's fingerprint is the expected one:
-- the directory's from the config, a listed shard's from the list, a private shard's from its invite link
-- (x4shard://host:port/code#fingerprint); a shard joined by a bare address is remembered by its first certificate.
-- First the directory gives the list of shards and the ship computer asks which to join (or the player types an
-- address, ui/x4shard_menu.lua). Login is automatic: Steam ID plus a signing key made once.
-- Spawns and despawns are asked from MD; other players' ships are placed here every frame after interpolating
-- the server snapshots: SetObjectSectorPos first, MD warp if the engine ignores it.
local ffi = require("ffi")
local C = ffi.C

-- One client per game: a copy from the Workshop and one copied by hand would both load (and both connect). Both
-- load within the same moment; the game's own UI reloads (new game, loaded save) come much later.
local loadedAt = getElapsedTime and getElapsedTime() or 0
if X4ShardLoadedAt and math.abs(loadedAt - X4ShardLoadedAt) < 2 then
	DebugError("[x4shard] a second copy of X4 Shard is installed, it stays idle: keep only one")
	return
end
X4ShardLoadedAt = loadedAt

-- The extension's own folder, where the network module is: the game lists its extensions with "location", the
-- folder's name under extensions\ (a mod manager may name it otherwise). Workshop copies cannot carry the module:
-- the X4 Workshop takes only catalogs, so this mod is not on the Workshop.
local function extensionFolder()
	local ok, list = pcall(GetExtensionList)
	if ok and type(list) == "table" then
		for _, e in ipairs(list) do
			if e.name == "X4 Shard" and e.enabled ~= false and not e.isworkshop
					and type(e.location) == "string" and e.location:match("^[%w%._%- ]+[/\\]?$") then
				return "extensions/" .. (e.location:gsub("[/\\]+$", "")) .. "/"
			end
		end
	end
	return "extensions/x4shard/"
end
local folder = extensionFolder()

local cfg = {
	host = "mc.idiot-home.ru",   -- directory: the shard that keeps the server list
	port = 47110,
	account = nil,           -- a plain account name instead of the Steam login (test setups)
	autopick = nil,          -- shard name to join without asking (test setups)
	dll = folder .. "native/x4shardnet_64.dll",   -- relative paths start at the game folder, the working directory
	sendInterval = 0.05,     -- own pose, s
	interpDelay = 0.15,      -- show other ships this far in the past, s
	maxExtrapolate = 0.35,   -- then hold, s
	connectTimeout = 5,      -- s; then close and retry
	retryAfter = 3,          -- s between connection attempts
	reportEvery = 10,        -- s between stats lines in the debug log
}

-- host, port (directory), account, autopick come from ui/x4shard_config.lua (loaded first by ui.xml)
if type(X4ShardConfig) == "table" then
	for key, value in pairs(X4ShardConfig) do
		cfg[key] = value
	end
end

local function log(text)
	DebugError("[x4shard] " .. text)
end

-- One declaration per pcall: vanilla menus declare the same types, a clash must not drop the rest.
local function declare(list)
	for _, decl in ipairs(list) do
		local ok, err = pcall(ffi.cdef, decl)
		if not ok and not tostring(err):find("redefin") then
			log("cdef failed: " .. decl .. " -> " .. tostring(err))
		end
	end
end

declare({
	"typedef uint64_t UniverseID;",
	"typedef struct { float x; float y; float z; float yaw; float pitch; float roll; } UIPosRot;",
	"UniverseID GetPlayerControlledShipID(void);",
	"UniverseID GetContextByClass(UniverseID componentid, const char* classname, bool includeself);",
	"UIPosRot GetObjectPositionInSector(UniverseID objectid);",
	"void SetObjectSectorPos(UniverseID objectid, UniverseID sectorid, UIPosRot offset);",
	"bool RequestDockAt(UniverseID containerid, bool checkonly);",
	"const char* RequestDockAtReason(UniverseID containerid, bool checkonly);",
	"const char* GetSteamID(void);",
	"const char* GetPlayerName(void);",
})

log("lua loaded from " .. folder)
local netlib, netlibError
local warnedNoNet = false

-- Identity: Steam ID plus an ECDSA P-256 key made once by the native module; shards get the public half and a
-- signature over their own challenge, never the key. It lives in the game's user data (X4ShardSaved, a saved
-- variable that Steam Cloud carries to the player's other PCs) and in %LOCALAPPDATA%\X4Shard\identity.key, in
-- case the game dies before it writes its user data. A shard binds the first public key it sees to the Steam ID.
X4ShardSaved = X4ShardSaved or {}
local identity = { steamid = "", key = nil, pub = nil, name = "Pilot" }

-- BCrypt private key blob as hex: magic "ECS2", coordinate size 32, then X, Y (the public key) and d
local function validKey(key)
	return type(key) == "string" and #key == 208 and key:match("^%x+$") ~= nil
		and key:sub(1, 16):lower() == "4543533220000000"
end

-- Called once, on the first tick of the X4 Shard start. Protected UI Mode (Settings > Extensions) removes
-- package.loadlib; the player has to turn it off for the network. We never switch it ourselves.
local function startNet()
	if type(package) == "table" and type(package.loadlib) == "function" then
		local open, err = package.loadlib(cfg.dll, "luaopen_x4shardnet")
		if open then
			local ok, lib = pcall(open)
			if ok then
				netlib = lib
			else
				netlibError = tostring(lib)
			end
		else
			netlibError = tostring(err)
		end
	else
		netlibError = "package.loadlib is not available"
	end
	if netlib and type(netlib.fingerprint) ~= "function" then   -- a module from before TLS (0.11) next to this file
		netlibError = "the network module is older than this X4 Shard (" .. tostring(netlib.version and netlib.version())
			.. "): install the mod again"
		netlib = nil
	end
	log(string.format("network module %s: protected_ui=%s %s", cfg.dll,
		tostring(GetUISafeModeOption and GetUISafeModeOption()),
		netlib and ("ready, version " .. tostring(netlib.version and netlib.version())) or ("failed: " .. tostring(netlibError))))
	if not netlib then
		return
	end
	local okId, steamid = pcall(function () return ffi.string(C.GetSteamID()) end)
	identity.steamid = (okId and steamid and steamid:match("^%d+$")) and steamid or ""
	local key = X4ShardSaved.key
	if not validKey(key) then
		key = netlib.load("identity.key")
	end
	if not validKey(key) then
		key = netlib.keygen()
	end
	if validKey(key) then
		identity.key, identity.pub = key, key:sub(17, 144):lower()
		X4ShardSaved.key = key
		netlib.save("identity.key", key)
	end
	local persona = netlib.persona()
	if not persona then
		local okName, playerName = pcall(function () return ffi.string(C.GetPlayerName()) end)
		persona = okName and playerName or nil
	end
	identity.name = ((persona or "Pilot"):gsub("[|\r\n\t]", " "))
	log(string.format("identity: %s steam=%s key=%s", identity.name, identity.steamid ~= "" and identity.steamid or "-",
		identity.pub and (identity.pub:sub(1, 8) .. "...") or "none"))
end

-- phase: "list" asks the directory, "pick" waits for the player's choice (also after a refused login or a shard
-- that does not answer), "play" is in a shard. A lost connection in "play" reconnects to the same shard.
local net = { state = "idle", since = 0, nextTry = 0, inbuf = "", outq = {}, phase = "list", target = nil,
	fails = 0, welcomed = false, choices = {} }
local servers = {}         -- the directory's list plus shards joined before: { name, host, port, players }
local BY_ADDRESS = "Connect by address..."
local stats = { rx = 0, tx = 0, moves = 0, placed = 0, errors = 0, nextReport = 0 }
local ents = {}            -- eid -> { kind, id, sector, snaps, lastSet, misses }
local spawnFifo = {}       -- eids waiting for MD to report the created component, in request order
local pendingEid = nil
local clockOffset = nil    -- server time minus local time, minimum observed delay
local moveVia = "ffi"
local nextSend = 0
local test = {}            -- scripted test from the server: mine = { ware, amount, interval, left, next }

local function now()
	return getElapsedTime()
end

local function split(line)
	local fields = {}
	for part in (line .. "|"):gmatch("([^|]*)|") do
		fields[#fields + 1] = part
	end
	return fields
end

local function notify(text)
	AddUITriggeredEvent("x4shard", "notify", { text })
end

local connectFailed        -- defined with the shard picker below

local function netClose(reason)
	netlib.close()
	net.state, net.inbuf, net.outq = "idle", "", {}
	net.nextTry = now() + cfg.retryAfter
	log("connection closed: " .. reason)
end

local function netOpen()
	local host, port = cfg.host, cfg.port
	if net.phase == "play" then
		host, port = net.target.host, net.target.port
	end
	local ok, err = netlib.open(host, port)
	net.nextTry = now() + cfg.retryAfter
	if not ok then
		log("connect to " .. host .. ":" .. port .. " failed: " .. tostring(err))
		connectFailed()
		return
	end
	net.state, net.since = "connecting", now()
	log("connecting to " .. host .. ":" .. port .. " (" .. net.phase .. ")")
end

local PROTO = "4"   -- TLS, and the login signature bound to the shard's certificate

local function helloLine()
	if cfg.account then
		return "HELLO|" .. cfg.account .. "|" .. PROTO .. "\n"
	elseif identity.pub then
		-- Steam ID may be empty (a game without Steam): the shard then knows the player by the key alone; a private
		-- shard also wants the invite code from the address the player was given
		local invite = net.target and net.target.invite
		return "HELLO|" .. identity.name .. "|" .. PROTO .. "|" .. identity.steamid .. "|" .. identity.pub
			.. (invite and ("|" .. invite) or "") .. "\n"
	end
	return "HELLO|" .. identity.name .. "|" .. PROTO .. "\n"
end

local listDone, pickAgain   -- defined with the shard picker below

-- The certificate the connection showed is the expected one (or the first one of a shard joined by bare address);
-- false: closed, and the player told.
local function certificateOk()
	local fp = netlib.fingerprint() or ""
	local want = net.phase == "list" and cfg.fingerprint or (net.target and net.target.fp)
	if want and want ~= "" and fp ~= want then
		netlib.close()
		net.state, net.inbuf, net.outq = "idle", "", {}
		if net.phase == "list" then
			log("the directory " .. cfg.host .. ":" .. cfg.port .. " showed certificate " .. fp .. ", expected " .. want)
			notify("X4 Shard: the server list did not show its known certificate, so it is not used. Shards joined before are offered.")
			net.fails, servers = 0, {}
			listDone()
		else
			log(net.target.name .. " showed certificate " .. fp .. ", expected " .. want)
			notify("X4 Shard: " .. net.target.name .. " showed another certificate than expected, so the game does not "
				.. "connect. If its owner reinstalled it, ask them for a new link.")
			pickAgain(3)
		end
		return false
	end
	if net.phase == "play" and not (want and want ~= "") then
		net.target.fp = fp   -- first visit by bare address: remembered with the shard (see remember)
		log("first visit to " .. net.target.name .. ": certificate " .. fp)
	end
	return true
end

-- Finishes a pending connect (TCP and TLS): the directory gets LIST, a shard gets HELLO.
local function netCheck()
	if net.state ~= "connecting" then
		return
	end
	local state, err = netlib.state()
	if state == "connected" then
		if not certificateOk() then
			return
		end
		net.state = "connected"
		if net.phase == "list" then
			servers = {}
			net.outq = { "LIST|" .. PROTO .. "\n" }
		else
			net.outq = { helloLine() }
		end
		log("connected (" .. net.phase .. ")")
	elseif state == "idle" then
		net.state = "idle"
		log("connect failed: " .. tostring(err))
		connectFailed()
	elseif now() - net.since > cfg.connectTimeout then
		netClose("connect timeout")
		connectFailed()
	end
end

local function queue(line)
	if net.state == "connected" then
		net.outq[#net.outq + 1] = line
	end
end

local function netFlush()
	while net.state == "connected" and #net.outq > 0 do
		local msg = net.outq[1]
		local n, err = netlib.send(msg)
		if not n then
			netClose("send: " .. tostring(err))
			return
		elseif n == #msg then
			table.remove(net.outq, 1)
			stats.tx = stats.tx + 1
		else
			net.outq[1] = msg:sub(n + 1)
			return
		end
	end
end

local handleLine

-- Lines that came with the close still count: a refusal (DENIED) arrives together with it.
local function netPoll()
	if net.state ~= "connected" then
		return
	end
	local closed
	for _ = 1, 16 do
		local data, err = netlib.recv()
		if not data then
			closed = "recv: " .. tostring(err)
			break
		elseif data == "" then
			break
		end
		net.inbuf = net.inbuf .. data
	end
	while true do
		local nl = net.inbuf:find("\n", 1, true)
		if not nl then
			break
		end
		local line = net.inbuf:sub(1, nl - 1)
		net.inbuf = net.inbuf:sub(nl + 1)
		stats.rx = stats.rx + 1
		handleLine(line)
	end
	if closed and net.state == "connected" then
		netClose(closed)
		if net.phase == "play" and not net.welcomed then
			connectFailed()   -- closed before letting the player in: three times and the list comes back
		end
	end
end

local function addressOf(s)
	return s.host .. ":" .. s.port
end

local function choose(s)
	net.target, net.phase, net.nextTry, net.fails, net.welcomed = s, "play", 0, 0, false
	log("joining " .. s.name .. " at " .. addressOf(s))
end

-- a certificate fingerprint as the shards give it: 64 hex digits, lower case
local function fingerprintOf(text)
	text = tostring(text or ""):lower()
	return (#text == 64 and text:match("^%x+$")) and text or nil
end

-- Shards joined before, most recent first (up to 5), as "name|host|port|invite|fingerprint" lines in the user data
-- and in %LOCALAPPDATA%\X4Shard\servers.txt: offered even when the directory is down or does not list them.
local function recentServers()
	local list = {}
	local text = X4ShardSaved.servers or netlib.load("servers.txt") or ""
	for line in tostring(text):gmatch("[^\n]+") do
		local f = split(line)
		local host, port = tostring(f[2]):match("^[%w%.%-]+$"), tonumber(f[3])
		if host and port then
			local invite = tostring(f[4] or ""):match("^%w+$")
			list[#list + 1] = { name = f[1], host = host, port = port, invite = invite, fp = fingerprintOf(f[5]) }
		end
	end
	return list
end

local function recentLine(s)
	return string.format("%s|%s|%d|%s|%s\n", (s.name:gsub("[|\n]", " ")), s.host, s.port, s.invite or "", s.fp or "")
end

local function remember(s)
	local lines = { recentLine(s) }
	for _, old in ipairs(recentServers()) do
		if #lines < 5 and addressOf(old) ~= addressOf(s) then
			lines[#lines + 1] = recentLine(old)
		end
	end
	X4ShardSaved.servers = table.concat(lines)
	netlib.save("servers.txt", X4ShardSaved.servers)
end

-- "host", "host:port" (default port 47110), with "/code" (a private shard's invite) and "#fingerprint" (its
-- certificate) or not, with "x4shard://" in front or not -> host, port, invite code, fingerprint
local function parseAddress(text)
	text = tostring(text or ""):gsub("^%s+", ""):gsub("%s+$", ""):gsub("^x4shard://", "")
	local fp
	text, fp = text:match("^([^#]*)#?(%x*)$")
	if not text or (fp ~= "" and not fingerprintOf(fp)) then
		return
	end
	fp = fingerprintOf(fp)
	local hostport, invite = text:match("^([^/]+)/(%w+)/?$")
	if not hostport then
		hostport = text:match("^([^/]+)/?$")
	end
	if not hostport then
		return
	end
	local host, port = hostport:match("^([%w%.%-]+):(%d+)$")
	if not host then
		host, port = hostport:match("^([%w%.%-]+)$"), "47110"
	end
	port = tonumber(port)
	if host and port and port >= 1 and port <= 65535 and (not invite or #invite <= 32) then
		return host, port, invite, fp
	end
end

-- The ship computer asks which shard to join (MD conversation, up to six choices): up to five shards ("*" on the
-- last one joined), then "by address", which opens the address window. Asked again if left unanswered.
local function showPicker()
	local labels = {}
	local last = recentServers()[1]
	net.choices = {}
	for _, s in ipairs(servers) do
		if #labels == 5 then
			break
		end
		local mark = (last and addressOf(s) == addressOf(last)) and " *" or ""
		local online = s.players and string.format(" (%s online)", s.players) or ""
		labels[#labels + 1] = s.name .. mark .. online
		net.choices[#labels] = s
	end
	labels[#labels + 1] = BY_ADDRESS
	net.choices[#labels] = "address"
	net.pickAgain = now() + 90
	AddUITriggeredEvent("x4shard", "servers", labels)
	log("server list shown: " .. table.concat(labels, ", "))
end

pickAgain = function (seconds)
	net.phase, net.pickAgain = "pick", now() + seconds
end

-- "By address": the window of ui/x4shard_menu.lua; while it is open the list waits, it comes back on Cancel.
local function chooseAddress()
	if not (X4ShardMenu and X4ShardMenu.open) then
		log("the address window is missing")
		return pickAgain(3)
	end
	pickAgain(3600)
	X4ShardMenu.open(X4ShardSaved.lastAddress or "")
end

-- Called by the address window
X4Shard = {
	joinAddress = function (text)
		local host, port, invite, fp = parseAddress(text)
		if not host then
			notify("X4 Shard: not a server address: " .. tostring(text))
			return pickAgain(3)
		end
		X4ShardSaved.lastAddress = text
		if not fp then   -- a bare address: the certificate this shard showed before, if the player was there
			for _, old in ipairs(recentServers()) do
				if old.host == host and old.port == port then
					fp = old.fp
				end
			end
		end
		choose({ name = host .. ":" .. port, host = host, port = port, invite = invite, fp = fp })
	end,
	cancelAddress = function ()
		pickAgain(0)
	end,
}

-- The directory's list is complete: add the shards joined before, join the configured one or let the player pick.
listDone = function ()
	netlib.close()
	net.state, net.inbuf, net.outq = "idle", "", {}
	for _, recent in ipairs(recentServers()) do
		-- names are unique in the directory: a listed shard keeps its listed address (at home that is its LAN one)
		local listed = false
		for _, s in ipairs(servers) do
			listed = listed or addressOf(s) == addressOf(recent) or s.name == recent.name
		end
		if not listed then
			servers[#servers + 1] = recent
		end
	end
	if cfg.autopick then
		for _, s in ipairs(servers) do
			if s.name == cfg.autopick then
				return choose(s)
			end
		end
	end
	net.phase = "pick"
	showPicker()
end

-- A connection attempt failed: the directory twice -> pick from the shards joined before or by address; a shard
-- that has not let the player in yet, three times -> the list again. A shard that did is retried (it restarts).
connectFailed = function ()
	net.fails = net.fails + 1
	if net.phase == "list" and net.fails >= 2 then
		log("the directory does not answer, offering the shards joined before")
		net.fails, servers = 0, {}
		listDone()
	elseif net.phase == "play" and not net.welcomed and net.fails >= 3 then
		notify("X4 Shard: " .. net.target.name .. " does not let you in")
		pickAgain(3)
	end
end

-- Scripted test docking (a player docks by hand): autopilot to a server station; once within 6 km ask for a
-- pad every 2 s (the request is refused from farther away), then MD lands the ship (dock_player_ship_at).
local function dockAt(eid)
	local e = ents[eid]
	if not (e and e.id) then
		log("dock: no station " .. tostring(eid))
		return
	end
	test.dock = { eid = eid, id = e.id, next = 0, tries = 0 }
	AddUITriggeredEvent("x4shard", "autopilot", { ConvertStringToLuaID(tostring(e.id)) })
	log("dock: autopilot to " .. eid)
end

local function dockStep(t)
	local d = test.dock
	if not d or t < d.next then
		return
	end
	d.next = t + 2
	local ship = C.GetPlayerControlledShipID()
	if ship == 0 then
		return
	end
	local a, b = C.GetObjectPositionInSector(ship), C.GetObjectPositionInSector(d.id)
	local dist = math.sqrt((a.x - b.x) ^ 2 + (a.y - b.y) ^ 2 + (a.z - b.z) ^ 2)
	if dist > 6000 then
		return
	end
	d.tries = d.tries + 1
	local granted = C.RequestDockAt(d.id, false)
	local reason = ffi.string(C.RequestDockAtReason(d.id, true))
	log(string.format("dock: %.0f m from %s, request granted=%s reason='%s'", dist, d.eid, tostring(granted), reason))
	if granted then
		AddUITriggeredEvent("x4shard", "dock", { ConvertStringToLuaID(tostring(d.id)) })
		test.dock = nil
	elseif d.tries >= 10 then
		log("dock: giving up")
		test.dock = nil
	end
end

handleLine = function (line)
	local f = split(line)
	local cmd = f[1]
	if cmd == "MOVE" then
		local e = ents[f[2]]
		if e then
			local t = tonumber(f[3])
			local offset = t - now()
			if (not clockOffset) or offset > clockOffset then
				clockOffset = offset
			end
			local snaps = e.snaps
			snaps[#snaps + 1] = { t = t, x = tonumber(f[4]), y = tonumber(f[5]), z = tonumber(f[6]),
				yaw = tonumber(f[7]), pitch = tonumber(f[8]), roll = tonumber(f[9]) }
			if #snaps > 32 then
				table.remove(snaps, 1)
			end
			stats.moves = stats.moves + 1
		end
	elseif cmd == "SPAWN" then
		local eid = f[2]
		if not ents[eid] then
			ents[eid] = { kind = f[3], snaps = {}, misses = 0 }
			spawnFifo[#spawnFifo + 1] = eid
			AddUITriggeredEvent("x4shard", "spawn", { eid, f[3], f[4], f[5], tonumber(f[6]), tonumber(f[7]),
				tonumber(f[8]), tonumber(f[9]), f[10] or "", f[11] or "" })
			log("spawn asked: " .. eid .. " " .. f[3] .. " " .. f[4] .. " '" .. (f[10] or "") .. "'")
		end
	elseif cmd == "DESPAWN" then
		local e = ents[f[2]]
		if e then
			if e.id then
				AddUITriggeredEvent("x4shard", "despawn", { ConvertStringToLuaID(tostring(e.id)) })
			end
			ents[f[2]] = nil
			log("despawn " .. f[2])
		end
	elseif cmd == "WALLET" then
		AddUITriggeredEvent("x4shard", "wallet", { tonumber(f[2]) })
		log("wallet " .. tostring(f[2]))
	elseif cmd == "CARGO" then
		AddUITriggeredEvent("x4shard", "cargo", { f[2], tonumber(f[3]) })
	elseif cmd == "TEST" and f[2] == "mine" then
		test.mine = { ware = f[3], amount = tonumber(f[4]), interval = tonumber(f[5]), left = tonumber(f[6]), next = now() }
		log("test: mining " .. f[4] .. " " .. f[3] .. " every " .. f[5] .. " s, " .. f[6] .. " times")
	elseif cmd == "TEST" and f[2] == "dock" then
		dockAt(f[3])
	elseif cmd == "SERVER" then
		local host, port = tostring(f[3]):match("^[%w%.%-]+$"), tonumber(f[4])
		if host and port then   -- the fingerprint is the one the directory saw when the shard registered
			servers[#servers + 1] = { name = f[2], host = host, port = port, players = f[5] or "0", fp = fingerprintOf(f[7]) }
		end
	elseif cmd == "END" then
		listDone()
	elseif cmd == "CHALLENGE" then
		-- a Steam login: sign the shard's random challenge (hex only, so nothing else gets signed) together with the
		-- certificate this connection showed: a shard that passes on another shard's challenge gets a signature
		-- the other one refuses
		local nonce = tostring(f[2]):match("^%x+$")
		local fp = netlib.fingerprint()
		local sig = nonce and fp and identity.key
			and netlib.sign(identity.key, "x4shard-login|" .. nonce .. "|" .. identity.steamid .. "|" .. fp)
		if sig then
			queue("PROOF|" .. sig .. "\n")
		else
			log("cannot sign the login challenge")
		end
	elseif cmd == "WELCOME" then
		net.welcomed, net.fails = true, 0
		net.target.name = tostring(f[5])
		remember(net.target)
		log("welcome pid=" .. tostring(f[2]) .. " as " .. tostring(f[4]) .. " on " .. tostring(f[5]))
		notify("X4 Shard: connected to " .. tostring(f[5]) .. " as " .. tostring(f[4]))
	elseif cmd == "DENIED" then
		-- the shard closes the connection; offer the list again, another shard may still take the player
		pickAgain(3)
		log("login refused by " .. net.target.name .. ": " .. tostring(f[2]))
		notify("X4 Shard: " .. net.target.name .. " refused the login - " .. tostring(f[2]))
	elseif cmd == "SAY" then
		notify("X4 Shard: " .. tostring(f[2]))
	end
end

local function angleLerp(a, b, k)
	local d = ((b - a + 180) % 360) - 180
	return a + d * k
end

local function poseAt(snaps, t)
	local n = #snaps
	if n == 0 then
		return nil
	end
	if n == 1 or t <= snaps[1].t then
		return snaps[1]
	end
	for i = n - 1, 1, -1 do
		local a, b = snaps[i], snaps[i + 1]
		if t >= a.t then
			if t <= b.t then
				local k = (t - a.t) / math.max(b.t - a.t, 1e-6)
				return { x = a.x + (b.x - a.x) * k, y = a.y + (b.y - a.y) * k, z = a.z + (b.z - a.z) * k,
					yaw = angleLerp(a.yaw, b.yaw, k), pitch = angleLerp(a.pitch, b.pitch, k), roll = angleLerp(a.roll, b.roll, k) }
			end
			break
		end
	end
	-- past the newest snapshot: continue with the last velocity for a while, then hold
	local a, b = snaps[n - 1], snaps[n]
	local span = math.max(b.t - a.t, 1e-6)
	local dt = math.min(t - b.t, cfg.maxExtrapolate)
	return { x = b.x + (b.x - a.x) / span * dt, y = b.y + (b.y - a.y) / span * dt, z = b.z + (b.z - a.z) / span * dt,
		yaw = b.yaw, pitch = b.pitch, roll = b.roll }
end

local posrot = ffi.new("UIPosRot")

local function placePuppets()
	if not clockOffset then
		return
	end
	local t = now() + clockOffset - cfg.interpDelay
	for eid, e in pairs(ents) do
		if e.kind == "puppet" and e.id then
			-- did the previous placement stick? (read back one frame later)
			if moveVia == "ffi" and e.lastSet then
				local p = C.GetObjectPositionInSector(e.id)
				local dx, dy, dz = p.x - e.lastSet.x, p.y - e.lastSet.y, p.z - e.lastSet.z
				if dx * dx + dy * dy + dz * dz > 50 * 50 then
					e.misses = e.misses + 1
					if e.misses >= 20 then
						moveVia = "md"
						log(string.format("SetObjectSectorPos does not stick (off by %.0f m), moving puppets with MD warp", math.sqrt(dx * dx + dy * dy + dz * dz)))
					end
				else
					e.misses = 0
				end
			end
			local pose = poseAt(e.snaps, t)
			if pose then
				if moveVia == "ffi" then
					posrot.x, posrot.y, posrot.z = pose.x, pose.y, pose.z
					posrot.yaw, posrot.pitch, posrot.roll = pose.yaw, pose.pitch, pose.roll
					C.SetObjectSectorPos(e.id, e.sector, posrot)
				else
					AddUITriggeredEvent("x4shard", "move", { ConvertStringToLuaID(tostring(e.id)), pose.x, pose.y, pose.z, pose.yaw, pose.pitch, pose.roll })
				end
				e.lastSet = { x = pose.x, y = pose.y, z = pose.z }
				stats.placed = stats.placed + 1
			end
		end
	end
end

local function sendOwnPose()
	local ship = C.GetPlayerControlledShipID()
	if ship == 0 then
		return
	end
	local sector = C.GetContextByClass(ship, "sector", false)
	if sector == 0 then
		return
	end
	local p = C.GetObjectPositionInSector(ship)
	local macro = GetComponentData(ConvertStringTo64Bit(tostring(sector)), "macro") or "?"
	queue(string.format("POS|%s|%.2f|%.2f|%.2f|%.2f|%.2f|%.2f\n", macro, p.x, p.y, p.z, p.yaw, p.pitch, p.roll))
end

local started = false

local function tick()
	if not started then
		started = true
		startNet()
	end
	if not netlib then
		if not warnedNoNet then
			warnedNoNet = true
			if type(package) ~= "table" or type(package.loadlib) ~= "function" then
				notify("X4 Shard: no network. Turn off Protected UI Mode in Settings > Extensions and restart the game.")
			else
				-- the game allows it, Windows did not: antivirus, Smart App Control
				notify("X4 Shard: the network module did not load (" .. tostring(netlibError) .. "). Your antivirus may have blocked it; see the mod page.")
			end
		end
		return
	end
	local t = now()
	if net.state == "idle" and (net.phase == "list" or net.phase == "play") and t >= net.nextTry then
		netOpen()
	end
	if net.phase == "pick" and t >= (net.pickAgain or 0) then
		showPicker()
	end
	netCheck()
	if net.state == "connected" and net.phase == "play" and net.welcomed and t >= nextSend then
		nextSend = t + cfg.sendInterval
		sendOwnPose()
	end
	netFlush()
	netPoll()
	placePuppets()
	local m = test.mine
	if m and m.left > 0 and t >= m.next then
		m.next, m.left = t + m.interval, m.left - 1
		AddUITriggeredEvent("x4shard", "testmine", { m.ware, m.amount })
	end
	dockStep(t)
	if t >= stats.nextReport then
		stats.nextReport = t + cfg.reportEvery
		local puppets = 0
		for _, e in pairs(ents) do
			if e.kind == "puppet" and e.id then
				puppets = puppets + 1
			end
		end
		log(string.format("stats state=%s rx=%d tx=%d moves=%d placed=%d puppets=%d move_via=%s clock_offset=%s errors=%d",
			net.state, stats.rx, stats.tx, stats.moves, stats.placed, puppets, moveVia, tostring(clockOffset), stats.errors))
	end
end

RegisterEvent("x4shard.tick", function ()
	local ok, err = pcall(tick)
	if not ok then
		stats.errors = stats.errors + 1
		if stats.errors <= 20 then
			log("tick error: " .. tostring(err))
		end
	end
end)

RegisterEvent("x4shard.spawned_eid", function (_, eid)
	pendingEid = eid
end)

RegisterEvent("x4shard.spawned", function (_, component)
	local eid = pendingEid or table.remove(spawnFifo, 1)
	pendingEid = nil
	for i, queued in ipairs(spawnFifo) do
		if queued == eid then
			table.remove(spawnFifo, i)
			break
		end
	end
	local e = eid and ents[eid]
	if not e then
		log("spawned component for unknown eid " .. tostring(eid))
		return
	end
	e.id = ConvertStringTo64Bit(tostring(component))
	e.sector = C.GetContextByClass(e.id, "sector", false)
	log("spawned " .. eid .. " id=" .. tostring(e.id) .. " sector=" .. tostring(e.sector))
end)

-- MD: the player chose a shard in the ship computer's conversation (section "x4shard_srv_<n>").
RegisterEvent("x4shard.pick", function (_, section)
	local choice = net.choices[tonumber(tostring(section):match("(%d+)$")) or 0]
	if net.phase ~= "pick" or not choice then
		return
	elseif choice == "address" then
		chooseAddress()
	else
		choose(choice)
	end
end)

-- MD saw the player's cargo grow ("ware|amount"): report it, the server decides how much counts.
RegisterEvent("x4shard.mined", function (_, text)
	local ware, amount = tostring(text):match("^([%w_]+)|(%d+)$")
	if ware then
		queue("MINED|" .. ware .. "|" .. amount .. "\n")
		log("mined " .. amount .. " " .. ware)
	end
end)

-- MD: the player's ship docked at a station the server put into the world; sell what its market buys.
RegisterEvent("x4shard.docked", function (_, station)
	local id = ConvertStringTo64Bit(tostring(station))
	for eid, e in pairs(ents) do
		if e.id == id then
			queue("SELL|" .. eid .. "|all|0\n")
			log("docked at " .. eid .. ", selling")
			return
		end
	end
	log("docked at a station the server does not know: " .. tostring(id))
end)
