mod cipher;
mod utils;

use cipher::Ghost;
use rand::{rngs::OsRng, RngCore};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use utils::{feedback_from_seed, hex_to_bytes_like_python};

const DUMMY_FLAG: &str = "fake_flag_for_local_testing";

fn inp() -> io::Result<String> {
    print!(">> ");
    io::stdout().flush()?;

    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn read_flag() -> String {
    if let Ok(flag) = env::var("FLAG") {
        if !flag.is_empty() {
            return flag;
        }
    }

    if let Ok(flag) = fs::read_to_string("/app/flag.txt") {
        return flag.trim().to_string();
    }

    DUMMY_FLAG.to_string()
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut seeds = [0u8; 2048 / 8];
    OsRng.fill_bytes(&mut seeds);
    println!("🌱 = {}", hex::encode(seeds));

    let feedback_index: usize = inp()?.trim().parse()?;
    assert!(feedback_index <= 2048 - 47);
    let feedback = feedback_from_seed(&seeds, feedback_index);

    let mut key = [0u8; 6];
    OsRng.fill_bytes(&mut key);
    let cipher = Ghost::new(&key, feedback);

    loop {
        let c: i32 = inp()?.trim().parse()?;
        if c == 1 {
            let pt = hex_to_bytes_like_python(&inp()?)?;
            let ct = cipher.encrypt(&pt);
            println!("{}", hex::encode(ct));
        }
        if c == 2 {
            let ct = hex_to_bytes_like_python(&inp()?)?;
            let pt = cipher.decrypt(&ct);
            println!("{}", hex::encode(pt));
        }
        if c == 3 {
            let mut pt = [0u8; 8];
            OsRng.fill_bytes(&mut pt);
            let ct = cipher.encrypt(&pt);
            println!("{}", hex::encode(ct));

            let guess = hex_to_bytes_like_python(&inp()?)?;
            if guess == pt {
                println!("{}", read_flag());
            } else {
                println!("You failed");
            }
            break;
        }
    }

    Ok(())
}

fn main() {
    run().unwrap();
}
