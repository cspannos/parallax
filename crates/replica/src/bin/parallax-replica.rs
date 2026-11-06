//! Worker process: stdin length-prefixed canonical inputs, stdout 32-byte roots.
//!
//! This is a replica, not a validator. Delay belongs in the driver.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clob::Genesis;
use protocol_types::{CanonicalDecode, GenesisBlob, Input};
use replica::{decode_hex, Replica, ReplicaOpts};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let wal = flag(&args, "--wal").ok_or("missing --wal")?;
    let key_hex = flag(&args, "--key-hex").ok_or("missing --key-hex")?;
    let genesis_hex = flag(&args, "--genesis-hex").ok_or("missing --genesis-hex")?;

    let key_bytes = decode_hex(&key_hex)?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "key-hex must be 32 bytes")?;
    let genesis_bytes = decode_hex(&genesis_hex)?;
    let blob = GenesisBlob::decode_slice(&genesis_bytes)?;
    let genesis = Genesis {
        height: blob.height,
        instruments: blob.instruments,
    };

    let (mut replica, _info) = Replica::open(ReplicaOpts::new(PathBuf::from(wal), key, genesis))?;

    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    loop {
        let mut len_buf = [0u8; 4];
        match read_exact_eof(&mut stdin, &mut len_buf)? {
            ReadEnd::Eof => break,
            ReadEnd::Full => {}
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 {
            break;
        }
        let mut payload = vec![0u8; len];
        stdin.read_exact(&mut payload)?;
        let input = Input::decode_slice(&payload)?;
        let receipt = replica.submit(input)?;
        stdout.write_all(&receipt.state_root.0)?;
        stdout.flush()?;
    }

    Ok(())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

enum ReadEnd {
    Full,
    Eof,
}

fn read_exact_eof(r: &mut impl Read, buf: &mut [u8]) -> io::Result<ReadEnd> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 if filled == 0 => return Ok(ReadEnd::Eof),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated length prefix",
                ))
            }
            n => filled += n,
        }
    }
    Ok(ReadEnd::Full)
}
