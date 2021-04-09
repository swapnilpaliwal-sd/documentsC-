//Project:Enigma
//Free for Distribution and use
#include <iostream>

#include "quadgram_analysis.h"
#include "enigma.h"

int main()
{	
	std::string key, ring_setting; 
	EnigmaText input;
	//Input the Key
	//display();
	std::cout << "-------------------------Commercial Enigma cipher-------------------------\n";
	std::cout<<"Please enter your plaintext: ";
	input.read_decrypted();
	//Input the Key and Encrypt
	std::cout<<"Enter the key (INCAPS) to establish a rotor sequence: ";
	std::cin>>key;
	std::cout<<"Enter potential ring settings (INCAPS): ";
	std::cin>>ring_setting;
	input.encrypt(key,ring_setting);
	//Display Ciphertext Results
	std::cout<<endl<<"Key Setting: "<<key<<'\n';
	std::cout<<"Ring Setting: "<<ring_setting<<"\n\n";
	std::cout<<"Output text: "<<input.encrypted<<'\n';
	
    return 0;
}
