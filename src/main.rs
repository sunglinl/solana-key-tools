use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::pubkey::Pubkey;
use aes::Aes256;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt,
    generic_array::GenericArray,
    KeyInit,
};
use rand::Rng;
use std::io::{self, Write, Read};
use std::fs::{File, OpenOptions};
use serde_json::Value;
use rpassword::read_password;

fn main() {
    loop {
        println!("Choose an option:");
        println!("1. Encrypt private key");
        println!("2. Decrypt private key and output pubkey");
        println!("3. Exit");
        println!("4. Decrypt private key and save to JSON file");

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();
        let choice = choice.trim();

        match choice {
            "1" => {
                encrypt_private_key();
            }
            "2" => {
                decrypt_private_key_and_output_pubkey();
            }
            "3" => {
                println!("Exiting...");
                break;
            }
            "4" => {
                decrypt_private_key_and_save_to_json();
            }
            _ => {
                println!("Invalid choice, please try again.");
            }
        }
    }
}

fn encrypt_private_key() {
    let keypair = Keypair::new();
    let pubkey: Pubkey = keypair.pubkey();

    let private_key = keypair.to_bytes();
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend_from_slice(&private_key);
    //println!("Generated Keypair: {:?}", buffer);

    let password = get_password();

    let encrypted = encrypt_to_array(&buffer, &password);
    println!("Encrypted private key as array: {:?}", encrypted);

    // Save encrypted data to JSON file
    let file_path = "encrypted_data.json";
    let json_output = serde_json::to_string(&encrypted).unwrap();
    let mut json_file = File::create(file_path).expect("Could not create JSON file");
    json_file.write_all(json_output.as_bytes()).expect("Could not write to JSON file");

    println!("Encrypted data saved to file as JSON array.");
}

fn decrypt_private_key_and_output_pubkey() {
    let mut file = File::open("encrypted_data.json").expect("Could not open file");
    let mut encrypted_data = String::new();
    file.read_to_string(&mut encrypted_data).expect("Could not read file");

    let encrypted_data: Vec<u8> = serde_json::from_str(&encrypted_data).expect("Could not parse JSON");
    //println!("encrypted_data:{:?}", encrypted_data);
    let password = get_password();

    let decrypted = decrypt_from_array(&encrypted_data, &password);
    //println!("decrypted_data:{:?}", decrypted);
    let keypair = Keypair::from_bytes(&decrypted).expect("Failed to create keypair from decrypted data");
    
    let pubkey = keypair.pubkey();
    println!("Decrypted pubkey: {}", pubkey);
}

fn decrypt_private_key_and_save_to_json() {
    let mut file = File::open("encrypted_data.json").expect("Could not open file");
    let mut encrypted_data = String::new();
    file.read_to_string(&mut encrypted_data).expect("Could not read file");

    let encrypted_data: Vec<u8> = serde_json::from_str(&encrypted_data).expect("Could not parse JSON");

    let password = get_password();

    let decrypted = decrypt_from_array(&encrypted_data, &password);

    // Create or open JSON file
    let file_path = "decrypted_private_keys.json";
    let mut json_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(file_path)
        .expect("Could not open JSON file");

    // Read existing JSON file content if present
    let mut file_content = String::new();
    json_file.read_to_string(&mut file_content).unwrap();

    // Parse file content as JSON array
    let mut json_array: Vec<Value> = if file_content.is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(&file_content).unwrap()
    };

    // Append decrypted private key byte array to JSON array
    //json_array.push(serde_json::json!(decrypted));
    let json_output = serde_json::to_string(&decrypted).unwrap();

    // Save JSON array to file in a compact format (single line)
    //let json_output = serde_json::to_string(&json_array).unwrap();
    let mut json_file = File::create(file_path).expect("Could not create JSON file");
    json_file.write_all(json_output.as_bytes()).expect("Could not write to JSON file");

    println!("Decrypted private key saved to 'decrypted_private_keys.json'.");
}

fn get_password() -> String {
    print!("Enter password: ");
    io::stdout().flush().unwrap();
    let password = read_password().unwrap();  // Hide user input
    password.trim().to_string()
}

fn encrypt_to_array(data: &[u8], key: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let key_bytes = key.as_bytes();
    let key_len = key_bytes.len();

    for (i, &byte) in data.iter().enumerate() {
        // 异或加密
        let encrypted_byte = byte ^ key_bytes[i % key_len];
        result.push(encrypted_byte);
    }

    result
}

fn decrypt_from_array(data: &[u8], key: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let key_bytes = key.as_bytes();
    let key_len = key_bytes.len();

    for (i, &byte) in data.iter().enumerate() {
        // 异或解密（异或是可逆的，加密和解密使用同样的操作）
        let decrypted_byte = byte ^ key_bytes[i % key_len];
        result.push(decrypted_byte);
    }

    result
}


