use std::io::{BufReader, BufWriter};

use crate::{
    args::DislodgeParams,
    crypto::{Crypto, DEFAULT_BUFFER_LEN},
    etcher,
};

pub async fn run_dislodge(args: DislodgeParams) -> anyhow::Result<()> {
    let in_path = &args.in_path.expect("a valid path to the input file");
    let out_path = &args.out_path.expect("a valid path to the output file");
    let decrypted_file_name = format!("{}_{}", in_path, uuid::Uuid::new_v4());

    let in_file = std::fs::File::open(in_path)?;
    let mut reader = BufReader::new(in_file);
    let decrypted_file = std::fs::File::create(&decrypted_file_name)?;
    let mut writer = BufWriter::new(decrypted_file);

    let crypto = Crypto::new(DEFAULT_BUFFER_LEN)?;
    crypto.decrypt(&mut reader, &mut writer)?;

    let out_data = etcher::read(in_path, 1)?;
    etcher::write_bytes(&out_path, out_data)?;
    Ok(())
}
