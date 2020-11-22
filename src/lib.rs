use std::env;
use std::fs;

pub struct Binary {
    pub name:    String,    // Name of the file
    pub content: Vec<u8>,   // The contents of the binary
    pub arch:    String,    // The architecture that was compiled
}

pub fn new_file() -> Result<Vec<u8>, &'static str> {
    // --snip--

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        return Err("not enough arguments");
    }

    let buff = read_file(args[1]).unwrap_or(println!("Couldn't open file"));

    Ok(buff)
}

fn read_file(flname: String) -> Result<Vec<u8>, &'static str> {
    match fs::read(flname) {
        Ok(f) => f,
        Err(err) => println!("You fucked it all"),
    }
}
