#pragma once

using namespace std;

class GenericCipherText {
public:
	string encrypted, decrypted;
	size_t length;
	double score;
	GenericCipherText(string t): encrypted{t}, decrypted{t}, length{t.length()}, score{min_quadgram_score} {}
	GenericCipherText(): encrypted{}, decrypted{}, length{0}, score{min_quadgram_score} {}
	void read_decrypted() {cin >> decrypted; encrypted=decrypted; length=decrypted.length();}
	virtual bool cryptanalysis() = 0;
	virtual string settings() = 0;
};
