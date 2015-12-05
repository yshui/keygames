import std.stdio;
import botan.pubkey.pubkey;
import botan.pubkey.algo.elgamal;
import botan.pubkey.algo.dl_group;
import botan.rng.rng;
import botan.rng.auto_rng;
import botan.math.bigint.bigint;
import botan.math.numbertheory.numthry;
import std.range, std.algorithm, std.string;
import std.socket, std.typecons;
import sign;
import botan.block.aes;


void main()
{
	/* Generate Keys
	auto rng = new AutoSeededRNG;
	auto priv = ElGamalPrivateKey(rng, DLGroup("dsa/jce/1024"));
	auto X = priv.getX.toString;
	auto Y = priv.getY.toString;
	auto G = priv.groupG.toString;
	auto P = priv.groupP.toString;
	auto outf = File("server.pub", "w");
	outf.writefln("%s\n%s\n%s\n", G, P, Y);

	outf = File("server.priv", "w");
	outf.writefln("%s\n%s\n%s\n", G, P, X);

	auto priv2 = ElGamalPrivateKey(rng, DLGroup("dsa/jce/1024"));
	auto X2 = priv2.getX.toString;
	auto Y2 = priv2.getY.toString;
	auto G2 = priv2.groupG.toString;
	auto P2 = priv2.groupP.toString;
	outf = File("client.pub", "w");
	outf.writefln("%s\n%s\n%s\n", G2, P2, Y2);

	outf = File("client.priv", "w");
	outf.writefln("%s\n%s\n%s\n", G2, P2, X2);
	*/
	//Read server= private key
	ubyte[] my_msg = cast(ubyte[])("We are connected".dup);
	my_msg.length = 16;
	auto inf = File("server.priv");
	auto rng = new AutoSeededRNG;
	auto X = BigInt(inf.byLine.drop(2).front.stripRight.idup);
	auto x = X.toString;
	auto priv = ElGamalPrivateKey(rng, DLGroup("dsa/jce/1024"), X.move);

	inf = File("client.pub");
	auto Y = BigInt(inf.byLine.drop(2).front.stripRight.idup);
	auto pub = ElGamalPublicKey(DLGroup("dsa/jce/1024"), Y.move);

	auto sock = new UdpSocket();
	char[] addr = "127.0.0.1".dup;
	auto saddr = scoped!InternetAddress(addr, cast(ushort)12345);
	Address src;
	sock.bind(saddr);

	auto de = new ElGamalDecryptionOperation(priv, rng);

	ubyte[4096] buf;
	while(true) {
		auto sz = sock.receiveFrom(buf, src);
		if (sz == Socket.ERROR)
			break;
		//writeln(buf[0..sz]);
		auto key_iv = de.decrypt(&buf[0], 256);
		auto sigr = de.decrypt(&buf[256], 256);
		auto sigs = de.decrypt(&buf[512], 256);

		if (pub.verify(sigr[]~sigs[], key_iv[])) {
			ubyte[] output = new ubyte[16];
			auto en = new AES256();
			en.setKey(key_iv.ptr, 32);
			en.encryptN(my_msg.ptr, output.ptr, 1);
			sock.sendTo(output, src);
		} else {
			ubyte[] output = new ubyte[16];
			sock.sendTo(output, src);
			writeln("Sig verify error");
		}
	}
}
