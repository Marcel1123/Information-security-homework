#include<iostream>
#include<fstream>
#include<sstream>
#include<string>
#include <cstring>
#include<openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>

using namespace std;
unsigned char * ciphertexts;
int ciphertext_len1;

unsigned char * new_ciphertexts = new unsigned char[4000];
int new_ciphertext_len1;

string from_decimal_to_hexadecimal(int number){
	string number_in_hexa = "";
	int i = 0;
	int local = 0;
	while(number != 0){
		 local = 0;
		 local = number % 16;
		 if(local < 10){
		 	number_in_hexa += (local + 48);
		 } else {
		 	number_in_hexa += (local + 55);
		 }
		 number = number / 16;
	}

	return number_in_hexa;
}

string prepary_for_encrypt_function(string key_in_word){
	string key_16;
	// convert the key from string to hexadecimal
	for(int i = 0; i < 16; i++){
    	if(i < key_in_word.length()){
    		key_16 += "\\x" + from_decimal_to_hexadecimal(int(key_in_word[i]));
    	} else {
    		key_16 += "\\x20";
    	}
    }

    return key_16;
}

string read_text_from_file(string file_name){
	ifstream f(file_name);
    string str;
	if(f) {
       ostringstream ss;
       ss << f.rdbuf();
       str = ss.str();
    }

    return str;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, string output_file, string algotirhm_selected)
{
    EVP_CIPHER_CTX *ctx;
    ciphertexts = new unsigned char[4000];

    int len;

    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(algotirhm_selected == "ECB"){
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
        	handleErrors();
    } else if(algotirhm_selected == "CBC"){
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        	handleErrors();
    } else if(algotirhm_selected == "CFB"){
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
        	handleErrors();
    } else if(algotirhm_selected == "OFB"){
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key, iv))
        	handleErrors();
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertexts, &len, plaintext, plaintext_len) )
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertexts + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    ofstream g(output_file);
    if(g){
    	g << ciphertexts;
    }

    return ciphertext_len;
}

int new_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, string output_file, string algotirhm_selected)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(algotirhm_selected == "ECB"){
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
        	handleErrors();
    } else if(algotirhm_selected == "CBC"){
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        	handleErrors();
    } else if(algotirhm_selected == "CFB"){
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
        	handleErrors();
    } else if(algotirhm_selected == "OFB"){
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key, iv))
        	handleErrors();
    }

    if(1 != EVP_EncryptUpdate(ctx, new_ciphertexts, &len, plaintext, plaintext_len) )
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, new_ciphertexts + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *key, unsigned char *iv, unsigned char *plaintext, string algotirhm_selected)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;
    // cout<<"1";
    plaintext = new unsigned char[4000];
    // cout<<"1";
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
// cout<<"2";
    if(algotirhm_selected == "ECB"){
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
        	handleErrors();
    } else if(algotirhm_selected == "CBC"){
    	// cout<<"3";
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        	handleErrors();
        // cout<<"4";
    } else if(algotirhm_selected == "CFB"){
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
        	handleErrors();
    } else if(algotirhm_selected == "OFB"){
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key, iv))
        	handleErrors();
    }
// cout<<"5";
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertexts, ciphertext_len1))
        handleErrors();
    plaintext_len = len;
// cout<<"6";
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;
// cout<<"7";
    EVP_CIPHER_CTX_free(ctx);
// cout<<"8";
    return plaintext_len;
}

int main(){
	string plaintext_file, criptotext_file;
	
	cout<< "Enter plaintext file name: ";
	cin>>plaintext_file;
	cout<<endl;
	
	cout<<"Enter criptotext file name: ";
	cin>>criptotext_file;
	cout<<endl;
	
	string text = "";
    string key = "";
    
    cout<<"Enter key: ";
    cin>>key;
    cout<<endl;

    cout<<"Select algoritm: ";
    string algoritm;
    cin>>algoritm;
    cout<<endl;

    int incercari = 0;

// cout<<"A W";
    string final_key = prepary_for_encrypt_function(key);
    // cout<<"A W";
    
    string iv = "\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f";
	int decryptedtext_len;
    // cout<<"A W";
    text = read_text_from_file(plaintext_file);
    // cout<<"A W";
    unsigned char* decripted_text;
    string new_key;
// cout<<"A W";
    ciphertext_len1 = encrypt ((unsigned char*)text.c_str(), text.length(), (unsigned char*)final_key.c_str(), (unsigned char*)iv.c_str(), criptotext_file, algoritm);

    string ciphertext1 = read_text_from_file(criptotext_file);

    ifstream st("words.txt");
    string normal_new_key;
    while(getline(st, new_key)){
    	normal_new_key = prepary_for_encrypt_function(new_key);
    	incercari = incercari + 1;
    	string new_text = read_text_from_file(plaintext_file);
    	new_ciphertext_len1 = new_encrypt((unsigned char*)new_text.c_str(), new_text.length(), (unsigned char*)normal_new_key.c_str(), (unsigned char*)iv.c_str(), criptotext_file, algoritm);

    	if(memcmp(ciphertexts, new_ciphertexts, strlen((char*)ciphertexts)) == 0){
    		break;
    	}
    	bzero(new_ciphertexts, 4000);
    }

    cout<< "Key is: "<<new_key<<endl;
    cout<<"Incercari: "<<incercari<<endl;
}
