use std::{
    fmt::Display,
    io::{BufReader, BufWriter},
};

use chacha20poly1305::{aead::stream, KeyInit, XChaCha20Poly1305};
use rand::{rngs::OsRng, RngCore};
use std::io::{Read, Write};

pub const DEFAULT_KEY_FILENAME: &str = "crypto.key";
pub const DEFAULT_NONCE_FILENAME: &str = "crypto.nonce";
pub const DEFAULT_BUFFER_LEN: usize = 512;

#[derive(Debug)]
pub enum Error {
    EncryptionError(chacha20poly1305::aead::Error),
    IOError(std::io::Error),
    InvalidSize(String),
}

impl From<chacha20poly1305::aead::Error> for Error {
    fn from(err: chacha20poly1305::aead::Error) -> Self {
        Error::EncryptionError(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IOError(err)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Error {:?}", self))
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Is a service able to encrypt or decrypt files.
pub struct Crypto {
    key: [u8; 32],
    nonce: [u8; 24],
    buffer_len: usize,
}

impl Crypto {
    pub fn new(buffer_len: usize) -> Result<Self> {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 24];

        // Checks if key and nonce files exists, if not then generate new a new key and nonce
        match std::fs::read(DEFAULT_KEY_FILENAME) {
            Ok(key_file) => {
                if key_file.len() != 32 {
                    return Err(Error::InvalidSize(format!(
                        "Expected key with 32 bytes, found {} bytes",
                        key_file.len()
                    )));
                }
                key.copy_from_slice(&key_file);
            }
            Err(_err) => {
                OsRng.fill_bytes(&mut key);
                std::fs::write(DEFAULT_KEY_FILENAME, &key)?;
            }
        };

        // This could be DRY, FIXME do a refactor here
        match std::fs::read(DEFAULT_NONCE_FILENAME) {
            Ok(nonce_file) => {
                if nonce_file.len() != 24 {
                    return Err(Error::InvalidSize(format!(
                        "Expected nonce with 24 bytes, found {} bytes",
                        nonce_file.len()
                    )));
                }
                nonce.copy_from_slice(&nonce_file);
            }
            Err(_err) => {
                OsRng.fill_bytes(&mut nonce);
                std::fs::write(DEFAULT_KEY_FILENAME, &nonce)?;
            }
        };

        Ok(Self {
            key,
            nonce,
            buffer_len,
        })
    }

    /// Encrypts the readed content into the writer.
    pub fn encrypt<R: Read, W: Write>(
        &self,
        reader: &mut BufReader<R>,
        writer: &mut BufWriter<W>,
    ) -> Result<()> {
        let cipher = XChaCha20Poly1305::new(&self.key.into());
        let mut stream = stream::EncryptorBE32::from_aead(cipher, self.nonce.as_ref().into());
        let mut buffer = vec![0u8; self.buffer_len];

        loop {
            let read_count = reader.read(&mut buffer)?;

            if read_count == self.buffer_len {
                let encrypted_text = stream.encrypt_next(buffer.as_slice())?;
                writer.write(&encrypted_text)?;
            } else {
                let encrypted_text = stream.encrypt_last(&buffer[..read_count])?;
                writer.write(&encrypted_text)?;
                break;
            }
        }
        let _ = writer.flush()?;
        Ok(())
    }

    /// Descrypts the readed content into the writer.
    pub fn decrypt<R: Read, W: Write>(
        &self,
        reader: &mut BufReader<R>,
        writer: &mut BufWriter<W>,
    ) -> Result<()> {
        let cipher = XChaCha20Poly1305::new(&self.key.into());
        let mut stream = stream::DecryptorBE32::from_aead(cipher, self.nonce.as_ref().into());
        let mut buffer = vec![0u8; self.buffer_len];

        loop {
            let read_count = reader.read(&mut buffer)?;

            if read_count == self.buffer_len {
                let decrypted_text = stream.decrypt_next(buffer.as_slice())?;
                writer.write(&decrypted_text)?;
            } else if read_count == 0 {
                break;
            } else {
                let decrypted_text = stream.decrypt_last(&buffer[..read_count])?;
                writer.write(&decrypted_text)?;
                break;
            }
        }
        let _ = writer.flush()?;
        Ok(())
    }
}

// TODO add some tests
