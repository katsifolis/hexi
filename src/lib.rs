use std::env;
use std::process;
use std::fs;
use std::io;

#[allow(dead_code)]
pub struct Buffer {
    content: Vec<u8>,
}

pub struct Binary {
    pub name:    String,    // Name of the file
    pub content: Vec<u8>,   // The contents of the binary
    pub arch:    String,    // The architecture that was compiled
}


pub fn draw_ui (data: Vec<u8>) -> Result<(), io::Error> {

    Ok(())

}

pub fn new_file() -> Result<Vec<u8>, ()> {
    // --snip--

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Didn't specify file");
        process::exit(1)
    } 
    let buff = read_file(args[1].clone()).unwrap();

    Ok(buff)
}

fn read_file(flname: String) -> Result<Vec<u8>, ()> {
    match fs::read(flname) {
        Ok(f) => Ok(f),
        Err(_) => {
            eprintln!("No such file");
            process::exit(1)
        },
    }
}
