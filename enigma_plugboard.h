//Project:Enigma
//Free for Distribution and use

#include <fstream>
#include <cstdio>
#include <algorithm>
#include "enigma.h"

using namespace std;

constexpr short plug_number {10};
const string kptfilename {"knownPlainText.txt"};

string print_plugboard_scores(const vector<vector<int>> &tracking) {
	string output {""};
	for(auto x: tracking){
		if(x[2] != -1) {
			for(int j=0;j<2;++j){
				output = output + alphabet[x[j]] + " ";
			}
			output = output + to_string(x[2]) + ", ";
		}
	}
	return output;
}

string read_from_kptfile(const string filename) {
	string known_plaintext;
	ifstream kptfile(filename);
	if (kptfile.is_open()) {
		string line;
		while ( getline (kptfile,line) ) { known_plaintext = known_plaintext + line; }
		kptfile.close();
	}
	return known_plaintext;
}

class EnigmaPlugboardText : public EnigmaText{
public:
	char sub_list[26];
	string known_plaintext;
	string plugboard_scores;
	EnigmaPlugboardText(string t): EnigmaText{t}, sub_list{}, known_plaintext{}, plugboard_scores{} {known_plaintext = read_from_kptfile(kptfilename); strncpy(sub_list, alphabet, 26);}
	EnigmaPlugboardText(): EnigmaText{}, sub_list{}, known_plaintext{}, plugboard_scores{} {known_plaintext = read_from_kptfile(kptfilename); strncpy(sub_list, alphabet, 26);}
	void read_decrypted() {
		cin >> decrypted;
		ofstream kptfile(kptfilename);
		if (kptfile.is_open()) { kptfile << decrypted; kptfile.close(); }
		else cout << "Unable to open known plaintext file for writing.\n";
		encrypted=decrypted; 
		length=decrypted.length();
	}
	void read_plugboard();
	void encrypt(const string key, const string ring_setting); 
	void plugboard_guess();
	void score_known_plaintext(size_t l);
	vector<int> location_of_best_loc(const int i, const int ignore);
	bool cryptanalysis();
	void remove_file() { remove(kptfilename.c_str()); }
	string settings() { return "Rotor Setting: "+rotor_setting()+"  Ring Setting: "+ring_setting()+"   Score: "+to_string(static_cast<int>(score))+plugboard_scores;}
};


void EnigmaPlugboardText::read_plugboard() {
	char loc_holder[2];
	for(short i=1; i<=plug_number; ++i) {
		//taking input of two credentials
		cout<<"#"<<i<<" plug at: ";
		cin>>loc_holder[0];
		cout<<"#"<<i<<" plug end at: ";
		cin>>loc_holder[1];
		sub_list[character_location(alphabet, loc_holder[0])] = loc_holder[1];
		sub_list[character_location(alphabet, loc_holder[1])] = loc_holder[0];
	}
}

void EnigmaPlugboardText::encrypt(const string key, const string ring_setting) {
	for(int i=0;i<length;++i){
		encrypted[i] = sub_list[character_location(alphabet,decrypted[i])];
	}
	initialize(key, ring_setting);
	encrypted = encryption_decryption(true);
	for(int i=0;i<length;++i){
		encrypted[i] = sub_list[character_location(alphabet,encrypted[i])];
	}
}

void EnigmaPlugboardText::plugboard_guess(){
	
	short location;
	string temp="";
	for(int j=0;j<length;++j){
		for(int i=0;i<26;++i){
			if(decrypted[j]==(alphabet[i])){
				location = i;
				temp = temp + sub_list[location];
			}
		}	
	}
	decrypted = temp;
}

void EnigmaPlugboardText::score_known_plaintext(size_t l){
    score = 0;
    for (int i=0;i<l;++i){
        if(decrypted[i]==known_plaintext[i]) ++score;
    }
}


vector<int> EnigmaPlugboardText::location_of_best_loc(const int i, const int ignore){
	
	vector<int> max {0,0,0};
	string orig_decrypted {decrypted};
	double counter {min_quadgram_score};
	char temp;
	string orig_settings[2] = {rotor_setting(),ring_setting()};
		
	for(int j=(i+1);j<26;++j){
		
		temp = sub_list[i];
		sub_list[i] = sub_list[j];
		sub_list[j] = temp;

		//PERMUTATIONS

		plugboard_guess();
		decrypted = encryption_decryption(false);
		plugboard_guess();
		
		score_known_plaintext(length);
		initialize(orig_settings[0], orig_settings[1]);

		//CHANGE TO ACCEPT DYNAMIC VALUES
		if(score>=counter && score>min(static_cast<const double>(length/5),28.0) && j!=ignore){
			counter = score;
			//cout<<"The Highest Counter: "<<counter<<" Rotor Setting: "<<rotor_setting()<<" Ring Setting: "<<ring_setting()<<'\n';
			//cout<<"Potential Plaintext: "<<decrypted<<'\n';
			//cout<<"Setting Used: "<<i<<" "<<j<<'\n'; 
			max = {i, j, static_cast<int>(counter)};
		}
			
		//Once the work is done close with this
		sub_list[j] = sub_list[i];
		sub_list[i] = temp;	
		decrypted = orig_decrypted;
		
	}
	return max;
}


bool EnigmaPlugboardText::cryptanalysis(){
	
	if (known_plaintext.length() == 0) return false;
	
		//Possible Key or Rotor Combination in Array all
	string all[17576];
	int l = 0;
	for(int i=0;i<26;++i){
		for(int j=0;j<26;++j){
			for(int k=0;k<26;++k){
				all[l] += all[l] + alphabet[i] + alphabet[j] + alphabet[k];
				++l;
			}
		}
	}	
	
	string key, ring_setting;
	double counter {min_quadgram_score};
	vector<int> old_text_score_result;
	
	vector<string> text_similar;
	
	[&] {
	for(int i=0;i<17576;++i){//Used for Varying Ring Setting
		
		for(int j=0;j<17576;++j){//Used for Varying Rotor Setting
			
			key = all[j];
			ring_setting = all[i];
			decrypt(key, ring_setting);
			score_known_plaintext(length);
			if(score>=counter){
				old_text_score_result.push_back(score);
				text_similar.push_back(decrypted);
				
				counter = score;
			
				if((text_similar.size() > 5) 
					&& (text_similar.at(text_similar.size()-1) == text_similar.at(text_similar.size()-2))
					&& (text_similar.at(text_similar.size()-1) == text_similar.at(text_similar.size()-3))
					
					) {
						
						initialize(key, ring_setting);
						return; 
					}					
			}	
		}
	}
	}();
	
	string rr_decrypted {decrypted};
	decrypted = encrypted;
	vector<vector<int>> tracking_one; 
	vector<vector<int>> tracking_two;
	vector<int> current_sub_loc;
	
	for(int i=0;i<26;++i){
		current_sub_loc = location_of_best_loc(i,-1);
		if(current_sub_loc[0]!=0 || current_sub_loc[1]!=0) tracking_one.push_back(current_sub_loc);
		current_sub_loc = location_of_best_loc(i,current_sub_loc[1]);
		if(current_sub_loc[0]!=0 || current_sub_loc[1]!=0) tracking_two.push_back(current_sub_loc);	
	}
	decrypted = rr_decrypted;
	plugboard_scores = print_plugboard_scores(tracking_one)+"\n\n"+print_plugboard_scores(tracking_two);
	if (plugboard_scores.length() > 2) {
		plugboard_scores = "\n\tPlugboard Settings can be Seen Below, Use Ones with Highest Scores:\n"+plugboard_scores;
		remove_file(); //delete known plaintext file if successfully matched
		return true;
	}
	else {
		plugboard_scores = "\n\tPlugboard Settings Could Not Be Found.";
		return false;
	}
}



