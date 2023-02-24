use std::{
    fmt::Display,
    io::{BufReader, BufWriter},
    sync::Arc,
};

use chacha20poly1305::{
    aead::{stream, Aead},
    KeyInit, XChaCha20Poly1305,
};
use rand::{rngs::OsRng, RngCore};
use std::io::{Read, Write};

use crate::etcher::read;

#[derive(Debug)]
pub enum Error {
    EncryptionError(chacha20poly1305::aead::Error),
    IOError(std::io::Error),
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

pub struct Crypto {
    key: [u8; 32],
    nonce: [u8; 24],
    buffer_len: usize,
}

impl Crypto {
    pub fn init(buffer_len: usize) -> Self {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);
        Self {
            key,
            nonce,
            buffer_len,
        }
    }

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
}
