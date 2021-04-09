#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <future>

#include "generic_cipher.h"

using namespace std;


constexpr char int_to_char [26] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};
const string for_comparison {"THEEUROPEANLANGUAGESAREMEMBERSOFTHESAMEFAMILYTHEIRSEPARATEEXISTENCEISAMYTHFORSCIENCEMUSICSPORTETCEUROPEUSESTHESAMEVOCABULARYTHELANGUAGESONLYDIFFERINTHEIRGRAMMARTHEIRPRONUNCIATIONANDTHEIRMOSTCOMMONWORDSEVERYONEREALIZESWHYANEWCOMMONLANGUAGEWOULDBEDESIRABLEONECOULDREFUSETOPAYEXPENSIVETRANSLATORSTOACHIEVETHISITWOULDBENECESSARYTOHAVEUNIFORMGRAMMARPRONUNCIATIONANDMORECOMMONWORDSIFSEVERALLANGUAGESCOALESCETHEGRAMMAROFTHERESULTINGLANGUAGEISMORESIMPLEANDREGULARTHANTHATOFTHEINDIVIDUALLANGUAGESTHENEWCOMMONLANGUAGEWILLBEMORESIMPLEANDREGULARTHANTHEEXISTINGEUROPEANLANGUAGESITWILLBEASSIMPLEASOCCIDENTALINFACTITWILLBEOCCIDENTALTOANENGLISHPERSONITWILLSEEMLIKESIMPLIFIEDENGLISHASASKEPTICALCAMBRIDGEFRIENDOFMINETOLDMEWHATOCCIDENTALISTHEEUROPEANLANGUAGESAREMEMBERSOFTHESAMEFAMILYTHEIRSEPARATEEXISTENCEISAMYTHFORSCIENCEMUSICSPORTETCEUROPEUSESTHESAMEVOCABULARYTHELANGUAGESONLYDIFFERINTHEIRGRAMMARTHEIRPRONUNCIATIONANDTHEIRMOSTCOMMONWORDSEVERYONEREALIZESWHYANEWCOMMONLANGUAGEWOULDBEDESIRABLEONECOULDREFUSETOPAYEXPENSIVETRANSLATORSTOACHIEVETHISITWOULDBENECESSARYTOHAVEUNIFORMGRAMMARPRONUNCIATIONANDMORECOMMONWORDSIFSEVERALLANGUAGESCOALESCETHEGRAMMAROFTHERESULTINGLANGUAGEISMORESIMPLEANDREGULARTHANTHATOFTHEINDIVIDUALLANGUAGESTHENEWCOMMONLANGUAGEWILLBEMORESIMPLEANDREGULARTHANTHEEXISTINGEUROPEANLANGUAGESITWILLBEASSIMPLEASOCCIDENTALINFACTITWILLBEOCCIDENTALTOANENGLISHPERSONITWILLSEEMLIKESIMPLIFIEDENGLISHASASKEPTICALCAMBRIDGEFRIENDOFMINETOLDMEWHATOCCIDENTALISTHEEUROPEANLANGUAGESAREMEMBERSOFTHESAMEFAMILYTHEIRSEPARATEEXISTENCEISAMYTHFORSCIENCEMUSICSPORTETCEUROPEUSESTHESAMEVOCABULARYTHELANGUAGESONLYDIFFERINTHEIRGRAMMARTHEIRPRONUNCIATIONANDTHEIRMOSTCOMMONWORDSEVERYONEREALIZESWHYANEWCOMMONLANGUAGEWOULDBEDESIRABLEONECOULDREFUSETOPAYEXPENSIVETRANSLATORSTOACHIEVETHISITWOULDBENECESSARYTOHAVEUNIFORMGRAMMARPRONUNCIATIONANDMORECOMMONWORDSIFSEVERALLANGUAGESCOALESCETHEGRAMMAROFTHERESULTINGLANGUAGEISMORESIMPLEANDREGULARTHANTHATOFTHEINDIVIDUALLANGUAGESTHENEWCOMMONLANGUAGEWILLBEMORESIMPLEANDREGULARTHANTHEEXISTINGEUROPEANLANGUAGESITWILLBEASSIMPLEASOCCIDENTALINFACTITWILLBEOCCIDENTALTOANENGLISHPERSONITWILLSEEMLIKESIMPLIFIEDENGLISHASASKEPTICALCAMBRIDGEFRIENDOFMINETOLDMEWHATOCCIDENTALISTHEEUROPEANLANGUAGESAREMEMBERSOFTHESAMEFAMILYTHEIRSEPARATEEXISTENCEISAMYTHFORSCIENCEMUSICSPORTETCEUROPEUSESTHESAMEVOCABULARYTHELANGUAGESONLYDIFFERINTHEIRGRAMMARTHEIRPRONUNCIATIONANDTHEIRMOSTCOMMONWORDSEVERYONEREALIZESWHYANEWCOMMONLANGUAGEWOULDBEDESIRABLEONECOULDREFUSETOPAYEXPENSIVETRANSLATORSTOACHIEVETHISITWOULDBENECESSARYTOHAVEUNIFORMGRAMMARPRONUNCIATIONANDMORECOMMONWORDSIFSEVERALLANGUAGESCOALESCETHEGRAMMAROFTHERESULTINGLANGUAGEISMORESIMPLEANDREGULARTHANTHATOFTHEINDIVIDUALLANGUAGESTHENEWCOMMONLANGUAGEWILLBEMORESIMPLEANDREGULARTHANTHEEXISTINGEUROPEANLANGUAGESITWILLBEASSIMPLEASOCCIDENTALINFACTITWILLBEOCCIDENTALTOANENGLISHPERSONITWILLSEEMLIKESIMPLIFIEDENGLISHASASKEPTICALCAMBRIDGEFRIENDOFMINETOLDMEWHATOCCIDENTALISTHEEUROPEANLANGUAGESAREMEMBERSOFTHESAMEFAMILYTHEIRSEPARATEEXISTENCEISAMYTHFORSCIENCEMUSICSPORTETCEUROPEUSESTHESAMEVOCABULARYTHELANGUAGESONLYDIFFERINTHEIRGRAMMARTHEIRPRONUNCIATIONANDTHEIRMOSTCOMMONWORDSEVERYONEREALIZESWHYANEWCOMMONLANGUAGEWOULDBEDESIRABLEONECOULDREFUSETOPAYEXPENSIVETRANSLATORSTOACHIEVETHISITWOULDBENECESSARYTOHAVEUNIFORMGRAMMARPRONUNCIATIONANDMORECOMMON"};


string key_update (string key_for_enc_n_dec, int plaintext_length){
    string temp = "";
    auto i {0};
    while(temp.length()!= plaintext_length) {
        temp = temp + key_for_enc_n_dec[i];
        ++i;
        if((i > 0) && ((i % (key_for_enc_n_dec.length())) == 0)){
            //Restart the sequence
            i = 0;
        }
    }
    return temp;
}

string text_trim_expand(const int &encrypted_text_length, const string compare_text) {
	string return_text = "";
	auto compare_text_length = compare_text.length();
	if(compare_text_length > encrypted_text_length){
		for(auto i=0; i < encrypted_text_length; i++) {
			return_text += compare_text[i];
		}
	}
	else{
		if(compare_text_length < encrypted_text_length) {
			for(auto i=0; i < encrypted_text_length; i++) {
				return_text += compare_text[i%compare_text_length];
			}
		}
		else{
			return_text = compare_text; 
		}
	}
	return return_text;
}


int encryption(int plaintext_ascii, int key) {

    int ciphertext {0};
	//Character by Character Encryption
    ciphertext = (plaintext_ascii + key)%26;

    return ciphertext;
}

int decryption(int ciphertext_ascii, int key) {

    int plaintext {0};
	//Character by Character Decryption
    plaintext = (ciphertext_ascii - key + 26)%26;

    return plaintext;
}

string integer_to_char (int ciphertext){

    string cipherchar = "";
    for (auto i=0; i<26; ++i) {

        if(ciphertext == i) {
            cipherchar = int_to_char [i];
        }

    }
    return cipherchar;
}

string encrypting (string plaintext, string key) {
	string ciphertext = "";
	vector<int> ascii_value_plaintext {};
	vector<int> ascii_value_key {};
	size_t key_length {key.length()};
	size_t message_length {plaintext.length()};
	vector<int> cipher_ascii {};


    for(auto i=0; i<message_length; ++i) {
        //Store Credentials as ASCII values
        ascii_value_plaintext.push_back((int)plaintext[i] - 65);
    }

    //Converting Key to cover plaintext
    if((key_length<message_length) || (key_length > message_length)) {
        //cout << "Key Length Cannot be Used" << endl;
        
        //cout << endl;
        //Key Repetition
        key = key_update(key, message_length);
        //cout << "The Updated key: " << key << endl;
    }

    // Converting Key String to ASCII
    for(auto i=0; i<message_length; ++i) {
        //Store Credentials as ASCII values
        ascii_value_key.push_back((int)key[i] - 65);
    }

    //Encrypting Character by Character
    for(auto i=0; i<message_length; ++i) {
        cipher_ascii.push_back(encryption (ascii_value_plaintext [i], ascii_value_key [i]));
    }
    //Integer to Character Conversion
    for(auto i=0; i<message_length; ++i) {
        ciphertext = ciphertext + integer_to_char (cipher_ascii[i]);
    }
    
    
    return ciphertext;
}

string decrypting (string ciphertext, string key) {
	string plaintext = "";
	vector<int> ascii_value_ciphertext {}; 
	vector<int> ascii_value_key {}; 
	size_t key_length {key.length()}; 
	size_t message_length {ciphertext.length()}; 
	vector<int> plain_ascii {};

    for(auto i=0; i<message_length; ++i) {
        //Store Credentials as ASCII values
        ascii_value_ciphertext.push_back((int)ciphertext[i] - 65);
    }
	
	//Converting Key to cover ciphertext
    if((key_length<message_length) || (key_length > message_length)) {
        //cout << "Key Length Cannot be Used" << endl;
        
        //Key Repetition
        key = key_update(key, message_length);
        //cout << "The Updated key: " << key << endl;
    }
	
	// Converting Key String to ASCII
    for(auto i=0; i<message_length; ++i) {
        //Store Credentials as ASCII values
        ascii_value_key.push_back((int)key[i] - 65);
    }
    //Decrypting Character by Character
    for(auto i=0; i<message_length; ++i) {
        plain_ascii.push_back(decryption (ascii_value_ciphertext [i], ascii_value_key [i]));
    }
    //Integer to Character Conversion
    for(auto i=0; i<message_length; ++i) {
        plaintext = plaintext + integer_to_char (plain_ascii[i]);
    }   
    
	return plaintext;
}


string truncate_key (const string key, const int key_len) {
	string truncate_final_key = "";
	for (auto i = 0; i< key_len; ++i) {
			truncate_final_key = truncate_final_key + key [i];
		}
	return truncate_final_key;
}


class VigenereText : public GenericCipherText{
public:
	string key;
	VigenereText(string t, size_t l): GenericCipherText{key_update(t,l)}, key{"AA"} {}
	VigenereText(string t): GenericCipherText{t}, key{"AA"} {}
	VigenereText(): GenericCipherText{}, key{"AA"} {}
	void encrypt(string k) {key=k; encrypted = encrypting(decrypted, key);}
	void encrypt() {cin >> key; encrypted = encrypting(decrypted, key);}
	void decrypt(string k) {key=k; decrypted = decrypting(encrypted,key);}
	void decrypt() {decrypted = decrypting(encrypted,key);}
	void quadgram_score(size_t l) {score = scoring_via_quadgram(decrypted,l);}
	void quadgram_score() {score = scoring_via_quadgram(decrypted,length);}
	double decryption_key_attempt_score (const int loc, const int i);
	string decryption_key_attempt (const int loc);
	bool cryptanalysis();
	string settings() { return "Key: "+key+"\nScore: "+to_string(score);}
};


double VigenereText::decryption_key_attempt_score (const int loc, const int i){
	string key_copy {key};
	key_copy[loc] =  int_to_char[i];
	key_copy = key_update(key_copy, length);
	return scoring_via_quadgram (decrypting (encrypted, key_copy), length);
}


string VigenereText::decryption_key_attempt (const int loc){

	double decryption_score_list[26];
	for (auto i = 0; i < 26; ++i) {
		std::future<double> score = std::async(&VigenereText::decryption_key_attempt_score, this, loc, i);
		decryption_score_list[i] = score.get();
	}
	
	int best_score_index = std::max_element(std::begin(decryption_score_list), std::end(decryption_score_list)) - std::begin(decryption_score_list);
	string return_key {key};
	return_key[loc] =  int_to_char[best_score_index];
	return return_key;
}


bool VigenereText::cryptanalysis() {
	
	quadgram_score();
	
	string base_text {for_comparison};
	//Using text_trim_expand function for dynamic size change
	auto ciphertext_length = encrypted.length();
	base_text = text_trim_expand(ciphertext_length,base_text);
	
	VigenereText compare {base_text, length};
	compare.quadgram_score();
	
	size_t best_key_length {length};
	double highest_score {min_quadgram_score};
	string best_decrypted {decrypted}, best_key {key};
	for (auto key_length = 2; key_length < length; ++key_length) {
		
		//Try not to repeat keys
		if (key_length > 2*best_key_length) break;
		
		//Guessing Keys character by character

		for (auto i = 0; i < key_length; ++i) {
			decrypt(decryption_key_attempt(i));
			quadgram_score();
			if ((highest_score < score) && (score > (1.15*compare.score))){
				highest_score = score;
				best_key_length = key_length;
				best_decrypted = decrypted;
				best_key = key;
			}
		}
		
		key = key + int_to_char[0];
	}
	decrypted = best_decrypted;
	key = best_key;
	score = highest_score;
	return true;
}
