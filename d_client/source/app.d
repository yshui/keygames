import std.stdio;
import botan.pubkey.pubkey;
import botan.pubkey.algo.elgamal;
import botan.pubkey.algo.dl_group;
import botan.rng.rng;
import botan.rng.auto_rng;
import botan.math.bigint.bigint;
import botan.math.numbertheory.numthry;
import botan.block.aes;
import std.range, std.algorithm, std.string;
import std.socket, std.typecons;
import sign;
import std.random;
import core.time;
import std.datetime;

auto array(R)(ref R r, int n) if (isInputRange!R) {
	auto ret = new ElementType!R[n];
	foreach(i; 0..n) {
		ret[i] = r.front;
		r.popFront;
	}
	return ret;
}

auto all(alias T, R)(R r) {
	foreach(i; r)
		if (!T(i))
			return false;
	return true;
}


void main()
{
	auto log = File("time.log", "w");
	auto inf = File("client.priv");
	auto rng = new AutoSeededRNG;
	auto X = BigInt(inf.byLine.drop(2).front.stripRight.idup);
	auto x = X.toString;
	auto priv = ElGamalPrivateKey(rng, DLGroup("dsa/jce/1024"), X.move);

	inf = File("server.pub");
	auto Y = BigInt(inf.byLine.drop(2).front.stripRight.idup);
	auto pub = ElGamalPublicKey(DLGroup("dsa/jce/1024"), Y.move);

	auto sock = new UdpSocket();
	char[] addr = "127.0.0.1".dup;
	auto saddr = scoped!InternetAddress(addr, cast(ushort)0);
	Address src;
	sock.bind(saddr);

	auto servaddr = scoped!InternetAddress("127.0.0.1".dup, cast(ushort)12345);

	auto de = new ElGamalEncryptionOperation(pub);

	ubyte[4096] buf;
	auto rng2 = Xorshift192(unpredictableSeed);
	while(true) {
		auto key = cast(ubyte[])array(rng2, 31);
		auto msg1 = de.encrypt(key.ptr, key.length, rng);
		auto sign = sign.sign(rng, priv, key);
		auto msg2 = de.encrypt(sign.ptr, 128, rng);
		auto msg3 = de.encrypt(&sign[128], 128, rng);
		StopWatch sw;

		sock.sendTo(msg1[]~msg2[]~msg3[], servaddr);
		sw.start();
		auto sz = sock.receiveFrom(buf, src);
		sw.stop();
		if (all!(a=>a==0)(buf[0..sz])) {
			writeln("We failed....");
			continue;
		}
		log.writeln(sw.peek().msecs/1e3);
		log.flush();
		writeln("Wait time: ", sw.peek().msecs/1e3);
		if (sz == Socket.ERROR)
			break;

		auto ade = new AES256();
		ade.setKey(key.ptr, 32);
		ubyte[] output = new ubyte[16];
		ade.decryptN(buf.ptr, output.ptr, 1);
		writeln("Recevied message: ", cast(char[])output);
	}
}
