-- X4 Shard client settings, read once when the game loads its UI. host/port is the directory: the shard that keeps
-- the list of public shards; the player picks one in the game or types the address of any other shard. fingerprint
-- is the SHA-256 of the directory's TLS certificate: the game talks to it only if it shows that certificate (the
-- list then gives the fingerprints of the shards in it). Login is by Steam account (nothing to fill in). Test setups
-- may add account = "<plain name>" (accepted only from the shard's own network) and autopick = "<shard name>".
X4ShardConfig = {
	host = "mc.idiot-home.ru",
	port = 47110,
	fingerprint = "7966662c7283d2e025998e031bbd64c94c2f64ede46e825fce1f9d57d39a10ff",
}
