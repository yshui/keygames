module sign;
import botan.rng.rng;
import botan.rng.auto_rng;
import botan.math.bigint.bigint;
import botan.math.numbertheory.numthry;
import botan.pubkey.algo.dl_algo;
import botan.pubkey.algo.dl_group;

ubyte[] sign(RandomNumberGenerator rng, in DLSchemePrivateKey key, ubyte[] msg) {
	BigInt m = BigInt(msg.ptr, msg.length);
	auto p = &key.groupP();
	auto pm1 = (*p)-1;

	if (m >= *p)
		throw new InvalidArgument("Message too long");

	BigInt sigr, sigs;
	while(true) {
		BigInt k = BigInt.randomInteger(rng, BigInt(2), pm1);
		while(gcd(k, pm1) != 1)
			k = BigInt.randomInteger(rng, BigInt(2), pm1);

		auto invk = inverseMod(k, pm1);
		sigr = powerMod(key.groupG(), k, *p);
		sigs = ((m-key.getX()*sigr)*invk) % pm1;
		if (sigs != 0)
			break;
	}

	ubyte[] output = new ubyte[2*p.bytes];
	sigr.binaryEncode(&output[p.bytes-sigr.bytes]);
	sigs.binaryEncode(&output[p.bytes*2-sigs.bytes]);
	return output;
}

bool verify(in DLSchemePublicKey key, ubyte[] sig, ubyte[] msg) {
	auto pb = key.groupP.bytes;
	auto p = key.groupP.dup;
	if (sig.length != 2*pb)
		return false;
	auto sigr = BigInt(sig.ptr, pb);
	auto sigs = BigInt(&sig[pb], pb);
	auto m = BigInt(msg.ptr, msg.length);
	if (m >= p)
		return false;

	if (sigr >= p || sigs >= p-1 || sigr == 0 || sigs == 0)
		return false;

	auto left = powerMod(key.groupG, m, p);
	auto right = (powerMod(key.getY, sigr, p)*powerMod(sigr, sigs, p)) % p;

	return left == right;
}
