use anyhow::anyhow;
use chacha20poly1305::{aead::{stream, NewAead}, XChaCha20Poly1305};
use rand::{rngs::OsRng, Rng};
use std::{env, fs::{File}, io::{Read, Write}};
use zeroize::Zeroize;

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err(anyhow!("Usage: cargo run -- <file>"));
    }

    let file = args[1].clone();
    if file.ends_with(".encrypted") {
        let dest = file.strip_suffix(".encrypted").unwrap().to_string() + ".decrypted";
        decrypt_file(&file, &dest)?;
    }
    else {
        let dest = file.clone() + ".encrypted";
        encrypt_file(&file, &dest)?;
    }
    Ok(())
}

fn encrypt_file (source_file_path: &str, dest_file_path: &str) -> Result<(), anyhow::Error> {
    let mut salt: [u8; 32] = OsRng.gen();
    let mut nonce: [u8; 19] = OsRng.gen();

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut source_file = File::open(source_file_path)?;
    let mut dest_file = File::create(dest_file_path)?;

    let aead = XChaCha20Poly1305::new(&derive_key(&salt).unwrap());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    dest_file.write_all(&salt)?;
    dest_file.write_all(&nonce)?;

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encryption failed: {}", err))?;
            dest_file.write_all(&ciphertext)?;
        }
        else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encryption failed: {}", err))?;
            dest_file.write_all(&ciphertext)?;
            break;
        }
    }

    nonce.zeroize();
    buffer.zeroize();
    salt.zeroize();

    Ok(())
}

fn decrypt_file (source_file_path: &str, dest_file_path: &str) -> Result<(), anyhow::Error> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];

    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut encrypted_file = File::open(source_file_path)?;
    let mut dest_file = File::create(dest_file_path)?;

    let read_salt = encrypted_file.read(&mut salt)?;
    if read_salt != salt.len() {
        return Err(anyhow!("Error reading salt."));
    }

    let read_nonce = encrypted_file.read(&mut nonce)?;
    if read_nonce != nonce.len() {
        return Err(anyhow!("Error reading nonce."));
    }

    let aead = XChaCha20Poly1305::new(&derive_key(&salt).unwrap());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dest_file.write_all(&plaintext)?;
        }
        else if read_count == 0 {
            break;
        }
        else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err|anyhow!("Decrypting large file: {}", err))?;
            dest_file.write_all(&plaintext)?;
            break;
        }
    }

    nonce.zeroize();
    buffer.zeroize();
    salt.zeroize();

    Ok(())
}

fn derive_key(salt: &[u8; 32]) -> Result<chacha20poly1305::Key, anyhow::Error> {
    let mut password = rpassword::prompt_password_stdout("password:")?;

    let config = &argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    };

    let key: [u8; 32] = argon2::hash_raw(password.as_bytes(), salt, config)
        .expect("")
        .try_into()
        .expect("");

    password.zeroize();
    Ok(key.into())
}
