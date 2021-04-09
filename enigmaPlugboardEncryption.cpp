//Project:Enigma
//Free for Distribution and use

/*
TRY FOR SETTINGS ZZZ XXX
THEWEATHERFORECASTTODAYISTWENTYTWODEGREECELSIUSPERCIPITATIONISLOWHUMIDITYISMODERATEANDWINDVELOCITYISHIGHWEAREALLCLEARFORTHEDAYTHEDRILLSCANBEPERFORMEDASDIRECTEDBYTHEGENERALNEXTUPDATEWILLBEDIRECTEDBYAIRFORCEWITHPRECISECONDITIONSHAILHITLER
THENAVYISALLCLEARFORTHEDAYITISTWELVEHUNDREDHOURWEAREALLSETFORTHEDAYWEAREMOVINGATASTEADYPACEWILLREACHTARGETINNEXTFEWDAYSWEAREADVICINGAIRFORCEANDARMYTOHELPUSEXPEDITETHEPROCESSBYPERFORMINGDAILYCOLLABORATEDDRILLSATFOURTEENHUNDREDHOURSHAILHITLER
JAPANATTACKEDPE
*/

#include <iostream>
#include <string>

#include "quadgram_analysis.h"
#include "enigma_plugboard.h"

int main()
{
	std::string key, ring_setting;
	EnigmaPlugboardText input;
	//Input the Text
	std::cout << "-------------------------Military Enigma cipher-------------------------\n";
	std::cout<<"Please enter your plaintext: ";
	input.read_decrypted();
	//Input the Key
	std::cout<<"Enter the key (INCAPS) to establish a rotor sequence: ";
	std::cin>>key;
	std::cout<<"Enter potential ring settings (INCAPS): ";
	std::cin>>ring_setting;
	//Input the Plugboard and Encrypt
	std::cout<<"\n------------------------------PLUGBOARD SETTINGS------------------------------\n";
	std::cout<<"Enter plug start and end points (INCAPS)...\n";
	input.read_plugboard();
	input.encrypt(key,ring_setting);
	//Display Ciphertext Results
	std::cout<<"\nKey Setting: "<<key<<'\n';
	std::cout<<"Ring Setting: "<<ring_setting<<"\n\n";
	std::cout<<"Output text: "<<input.encrypted<<'\n';
	
	return 0;
}
