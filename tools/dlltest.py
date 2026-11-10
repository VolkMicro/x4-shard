"""The network module outside the game, on Windows: the game's own lua51_64.dll (LuaJIT) runs a Lua script that
loads x4shardnet_64.dll the way the extension does and talks TLS to a local shard.

Checks: the server list over TLS with the shard's fingerprint, a signed login, 120 KB in one send (several TLS
records), the shard closing the connection, a port where nothing listens, a server that does not speak TLS.

usage: python -I tools/dlltest.py <x4shardnet_64.dll> [X4 folder, default D:\\SteamLibrary\\steamapps\\common\\X4 Foundations]
"""
import ctypes
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT, PLAIN_PORT, DEAD_PORT = 47195, 47194, 47193

LUA = r"""
local net = assert(package.loadlib(DLL, "luaopen_x4shardnet"))()
local ffi = require("ffi")
ffi.cdef("void Sleep(unsigned long ms);")
print("module version " .. net.version())

local function connect(port)
  assert(net.open("127.0.0.1", port))
  for _ = 1, 500 do
    local state, err = net.state()
    if state == "connected" then return true end
    if state == "idle" then return false, err end
    ffi.C.Sleep(10)
  end
  return false, "timeout"
end

local buf = ""
local function read_until(want, ms)
  local lines = {}
  for _ = 1, ms / 10 do
    local data, err = net.recv()
    if not data then return lines, err end
    buf = buf .. data
    while true do
      local nl = buf:find("\n", 1, true)
      if not nl then break end
      local line = buf:sub(1, nl - 1)
      buf = buf:sub(nl + 1)
      lines[#lines + 1] = line
      if want and line:find(want) then return lines end
    end
    ffi.C.Sleep(10)
  end
  return lines, "timeout"
end

-- the list, and the fingerprint the shard showed
local ok, err = connect(PORT)
assert(ok, "connect: " .. tostring(err))
print("fingerprint " .. tostring(net.fingerprint()))
assert(net.send("LIST|4\n") == 7)
local lines = read_until("^END$", 3000)
for _, l in ipairs(lines) do print("list: " .. l) end
assert(lines[#lines] == "END", "no END")
net.close()

-- a signed login without Steam, by the key alone
local key = net.keygen()
local pub = key:sub(17, 144):lower()
buf = ""
assert(connect(PORT))
net.send("HELLO|DllTest|4||" .. pub .. "\n")
lines = read_until("^CHALLENGE", 3000)
local nonce = lines[#lines]:match("^CHALLENGE|(%x+)$")
assert(nonce, "no challenge")
-- signed together with the certificate this connection showed (protocol 4)
net.send("PROOF|" .. net.sign(key, "x4shard-login|" .. nonce .. "||" .. net.fingerprint()) .. "\n")
lines = read_until("^WELCOME", 3000)
print("login: " .. lines[#lines])
assert(lines[#lines]:find("^WELCOME|%d+|[%d%.]+|DllTest|"), "no welcome")

-- 120 KB at once: TLS records of at most 16 KB each, all of it taken or nothing
local many = {}
for i = 1, 2000 do many[i] = string.format("POS|cluster_13_sector001_macro|%d.00|0.00|-7000.00|0.00|0.00|0.00\n", i % 50) end
local big = table.concat(many)
local taken = 0
for _ = 1, 100 do
  taken = net.send(big)
  if taken > 0 then break end
  ffi.C.Sleep(10)
end
print(string.format("big send: %d of %d bytes", taken, #big))
assert(taken == #big)
read_until(nil, 500)

-- the shard closes: what it sent before the close still arrives, then "closed"
net.send("BYE\n")
local _, closed = read_until(nil, 3000)
print("after BYE: " .. tostring(closed))
assert(closed == "closed")

-- nothing listens there
ok, err = connect(DEAD_PORT)
print("dead port: " .. tostring(err))
assert(not ok)

-- a server without TLS
ok, err = connect(PLAIN_PORT)
print("plain server: " .. tostring(err))
assert(not ok and tostring(err):find("^tls") or tostring(err):find("closed"))
print("DLLTEST OK")
"""


def plain_server():
    """Answers in plain text, like a shard before 0.12."""
    lsock = socket.create_server(("127.0.0.1", PLAIN_PORT))
    while True:
        conn, _ = lsock.accept()
        try:
            conn.recv(4096)
            conn.sendall(b"DENIED|plain text here\n")
        finally:
            conn.close()


def main():
    dll = os.path.abspath(sys.argv[1])
    game = sys.argv[2] if len(sys.argv) > 2 else r"D:\SteamLibrary\steamapps\common\X4 Foundations"
    tmp = tempfile.mkdtemp()
    shard = subprocess.Popen([sys.executable, "-I", os.path.join(ROOT, "server", "shard_server.py"), "--host",
                              "127.0.0.1", "--port", str(PORT), "--name", "Dll Test", "--directory", "--accounts",
                              os.path.join(tmp, "a.json")], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    threading.Thread(target=plain_server, daemon=True).start()
    time.sleep(1.5)
    try:
        os.add_dll_directory(game)
        lua = ctypes.CDLL(os.path.join(game, "lua51_64.dll"))
        lua.luaL_newstate.restype = ctypes.c_void_p
        lua.luaL_openlibs.argtypes = [ctypes.c_void_p]
        lua.luaL_loadstring.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lua.lua_pcall.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
        lua.lua_tolstring.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
        lua.lua_tolstring.restype = ctypes.c_char_p
        state = lua.luaL_newstate()
        assert state, "luaL_newstate failed"
        lua.luaL_openlibs(state)
        script = "DLL = [[%s]]\nPORT, PLAIN_PORT, DEAD_PORT = %d, %d, %d\n%s" % (dll, PORT, PLAIN_PORT, DEAD_PORT, LUA)
        if lua.luaL_loadstring(state, script.encode()) or lua.lua_pcall(state, 0, 0, 0):
            print("LUA ERROR: " + lua.lua_tolstring(state, -1, None).decode(errors="replace"), flush=True)
            return 1
        return 0
    finally:
        shard.terminate()
        log = shard.communicate(timeout=5)[0].decode(errors="replace")
        print("--- shard log", flush=True)
        print("\n".join(l for l in log.splitlines() if " status " not in l))


if __name__ == "__main__":
    sys.exit(main())
