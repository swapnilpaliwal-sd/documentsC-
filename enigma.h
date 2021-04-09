//Project:Enigma
//Free for Distribution and use
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

#include "generic_cipher.h"

using namespace std;

constexpr char alphabet[26] {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};
constexpr char rotor_one_cred[26] {'E','K','M','F','L','G','D','Q','V','Z','N','T','O','W','Y','H','X','U','S','P','A','I','B','R','C','J'};
constexpr char rotor_two_cred[26] {'A','J','D','K','S','I','R','U','X','B','L','H','W','T','M','C','Q','G','Z','N','P','Y','F','V','O','E'};
constexpr char rotor_three_cred[26] {'B','D','F','H','J','L','C','P','R','T','X','V','Z','N','Y','E','I','W','G','A','K','M','U','S','Q','O'};
constexpr char reflector[26] {'A','B','C','D','E','F','G','D','I','J','K','G','M','K','M','I','E','B','F','T','C','V','V','J','A','T'};


class Rotor {
	public:
	//input element on the rotor
	char input_character[26];
	//output element from the rotor
	char output_character[26];
	Rotor(char const r[]): input_character{}, output_character{} {
		strncpy(input_character, alphabet, 26);
		strncpy(output_character, r, 26);
	}
	Rotor(): input_character{}, output_character{} {
		strncpy(input_character, alphabet, 26);
	}
};


short character_location(const char rotor_input[], const char character_input){
	return distance(rotor_input, find(rotor_input, rotor_input+26, character_input));
}

void rotor_shift(char rotor_input[], const int position){
	char character_holder=rotor_input[0];
	for(int i=0;i<position;++i){
		character_holder=rotor_input[0];
		for(int j=0;j<25;++j){
			rotor_input[j]=rotor_input[j+1];
			if(j==24){
				rotor_input[25]=character_holder;
			}
		}
	}
}


class EnigmaText : public GenericCipherText{
public:
	Rotor rotor_one, rotor_two, rotor_three;
	EnigmaText(string t): GenericCipherText{t}, rotor_one {rotor_one_cred}, rotor_two {rotor_two_cred}, rotor_three {rotor_three_cred} {}
	EnigmaText(): GenericCipherText{}, rotor_one {rotor_one_cred}, rotor_two {rotor_two_cred}, rotor_three {rotor_three_cred} {}
	short rotor_direction_output(const short input_output_char_loc);
	void initialize(string key, string ring_setting);
	string encryption_decryption(bool decryption);
	void encrypt(string key, string ring_setting) {initialize(key, ring_setting); encrypted = encryption_decryption(false);}
	void decrypt(string key, string ring_setting) {initialize(key, ring_setting); decrypted = encryption_decryption(true);}
	void quadgram_score(size_t l) {score = scoring_via_quadgram(decrypted,l);}
	void quadgram_score() {score = scoring_via_quadgram(decrypted,length);}
	string rotor_setting() {string s {rotor_one.input_character[0],rotor_two.input_character[0],rotor_three.input_character[0]}; return s;}
	string ring_setting() {string s {rotor_one.output_character[0],rotor_two.output_character[0],rotor_three.output_character[0]}; return s;}
	bool cryptanalysis();
	string settings() { return "Rotor Setting: "+rotor_setting()+"  Ring Setting: "+ring_setting()+"   Score: "+to_string(score);}
};

short EnigmaText::rotor_direction_output(const short input_output_char_loc){
		
		short characher_location_holder {input_output_char_loc};
		short characher_location_holder_two;
		
		//Getting character on rotor3 input tray
		characher_location_holder=character_location(rotor_three.input_character,rotor_three.output_character[characher_location_holder]);
		//Getting character on rotor2 input tray
		characher_location_holder=character_location(rotor_two.input_character,rotor_two.output_character[characher_location_holder]);
		//Getting character on rotor1 input tray
		characher_location_holder=character_location(rotor_one.input_character,rotor_one.output_character[characher_location_holder]);
		//Getting the reflected elment and the other reflected value
	
		for(int i=0;i<26;++i){
			if(characher_location_holder!=i && reflector[characher_location_holder]==reflector[i]){
				characher_location_holder_two=i;
			}
		}
		
		//Getting character on rotor1 output tray
		characher_location_holder=character_location(rotor_one.output_character,rotor_one.input_character[characher_location_holder_two]);
		//Getting character on rotor2 output tray
		characher_location_holder=character_location(rotor_two.output_character,rotor_two.input_character[characher_location_holder]);
		//Getting character on rotor3 output tray
		characher_location_holder=character_location(rotor_three.output_character,rotor_three.input_character[characher_location_holder]);
		//Cipher Character
		return characher_location_holder;
		
}


void EnigmaText::initialize(const string key, const string ring_setting) {
	
	short location_on_initialization_array;
	
	//Get the character location on the input character array for rotor1
	location_on_initialization_array=character_location(rotor_one.output_character,ring_setting[0]);
	rotor_shift(rotor_one.output_character,location_on_initialization_array);
			
	//Initialize with ring setting location 
	location_on_initialization_array = character_location(rotor_one.input_character,key[0]);
	rotor_shift(rotor_one.input_character,location_on_initialization_array);
			
	//Get the character location on the input character array for rotor2
	location_on_initialization_array=character_location(rotor_two.output_character,ring_setting[1]);
	rotor_shift(rotor_two.output_character,location_on_initialization_array);
			
	//Initialize with ring setting location 
	location_on_initialization_array = character_location(rotor_two.input_character,key[1]);
	rotor_shift(rotor_two.input_character,location_on_initialization_array);
			
	//Get the character location on the input character array for rotor3
	location_on_initialization_array=character_location(rotor_three.output_character,ring_setting[2]);
	rotor_shift(rotor_three.output_character,location_on_initialization_array);
			
	//Initialize with ring setting location 
	location_on_initialization_array = character_location(rotor_three.input_character,key[2]);
	rotor_shift(rotor_three.input_character,location_on_initialization_array);
}


string EnigmaText::encryption_decryption(const bool decryption) {
	
	//Creating Input/Output Array
	string output_text;
	short char_loc_holder;
	int count_rotor_one {0}, count_rotor_two {0}, count_rotor_three {0};
	
	for(int i=0;i<length;++i){
		
		//Finding the location of the character on the input output tray
		if(decryption) {char_loc_holder=character_location(alphabet,encrypted[i]);}
		else {char_loc_holder=character_location(alphabet,decrypted[i]);}
		//Step1
		//shifting the rotor3 by one place
		rotor_shift(rotor_three.input_character,1);
		rotor_shift(rotor_three.output_character,1);
		++count_rotor_three;
		//if we complete a complete rotation move second rotor
		if((count_rotor_three>0)&&(count_rotor_three%26==0)){
			rotor_shift(rotor_two.input_character,1);
			rotor_shift(rotor_two.output_character,1);
			++count_rotor_two;
			//if we complete a complete rotation move first rotor
			if((count_rotor_two>0)&&(count_rotor_two%26==0)){
				rotor_shift(rotor_one.input_character,1);
				rotor_shift(rotor_one.output_character,1);
				++count_rotor_one;
			}
		}
		char_loc_holder=rotor_direction_output(char_loc_holder);
		output_text += alphabet[char_loc_holder];
	}
	return output_text;
}


bool EnigmaText::cryptanalysis(){
	
		//Possible Key or Rotor Combination in Array all
	//display();

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

	for(int i=0;i<17576;++i){//Used for Varying Ring Setting
		
		for(int j=0;j<17576;++j){//Used for Varying Rotor Setting
			
			key = all[j];
			ring_setting = all[i];
			decrypt(key, ring_setting);
			quadgram_score();
			if(score>=counter){
				old_text_score_result.push_back(score);
				counter = score;
				
				if((old_text_score_result.size() > 3) 
					&& (old_text_score_result.at(old_text_score_result.size()-1) == old_text_score_result.at(old_text_score_result.size()-2)) 
					&& (old_text_score_result.at(old_text_score_result.size()-1) == old_text_score_result.at(old_text_score_result.size()-3))) {
						//reassign rotor settings
						rotor_one.input_character[0] = key[0];
						rotor_two.input_character[0] = key[1];
						rotor_three.input_character[0] = key[2];
						
						//reassign ring settings
						rotor_one.output_character[0] = ring_setting[0];
						rotor_two.output_character[0] = ring_setting[1];
						rotor_three.output_character[0] = ring_setting[2];
						
						
						return true; 
					}
						
			}	
		}
	}
	return false;
}


