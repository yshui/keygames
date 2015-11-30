import std.stdio;
import botan.pubkey.pubkey;
import botan.pubkey.algo.elgamal;
import botan.pubkey.algo.dl_group;
import botan.rng.rng;
import botan.rng.auto_rng;

void main()
{
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
}
