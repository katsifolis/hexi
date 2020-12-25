#![warn(unused_extern_crates)]
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Stdout;
use std::io::Write;
use std::process;
use std::thread;
use std::time;
use termion::event::Key;
use termion::input::{TermRead, TermReadEventsAndRaw};
use termion::raw::{IntoRawMode, RawTerminal};
use termion::{async_stdin, clear, cursor, terminal_size};

#[allow(dead_code)]
/// Contains info about the binary file
pub struct Binary {
    pub name: String,    // Name of the file
    pub buffer: Vec<u8>, // The contents of the binary
}

#[derive(Hash)]
pub struct Cell {
    x: u8,
    y: u8,
    rune: u16,
}
#[derive(PartialEq)]
/// Number Represantation at various bases
pub enum Repr {
    BINARY,
    OCTAL,
    DECIMAL,
    HEX,
    ASCII,
}

#[allow(dead_code)]
fn scrl() -> fn(u16) -> (u16, u16) {
    |x| {
        if x > 5 {
            (x - 5, 0)
        } else {
            (0, 0)
        }
    }
}

/// returns with default values they byte representation of the file
/// in cols of 5 and in rows of <file_size/5>
pub fn get_data_repr(_data: Vec<u8>, format: Repr, s: usize, o: usize) -> Vec<String> {
    let mut values = Vec::<String>::new();
    let mut tmp = String::from("");
    for (idx, v) in _data[s..o].iter().enumerate() {
        match format {
            Repr::HEX => {
                tmp.push_str(&*String::from(format!("{:02X}", v))) // passing the values;
            }
            Repr::ASCII => {
                if *v > 0x20 && *v < 0x7f {
                    tmp.push_str(&*String::from(format!("{}", *v as char)));
                } else {
                    tmp.push_str(&*String::from(format!(".")));
                }
            }
            _ => (),
        }

        if (idx + 1) % 16 == 0 {
            tmp.push_str("\n");
            let res = tmp.clone();
            values.push(res);
            tmp.clear();
        }
    }
    values
}

pub fn term_clear(file: &mut RawTerminal<Stdout>) -> Result<(), (io::Error)> {
    write!(file, "{}", termion::clear::All);
    file.flush()
}

/// returns a string representation of address in hex format with offset from
/// 0 and length of the number
pub fn get_addr_repr<'a>(s: usize, o: usize, length: usize) -> HashMap<usize, String> {
    (s..o)
        .map(|x| (x, format!("{:01$X}", x * 0x10, length)))
        .collect::<HashMap<usize, String>>()
}

pub fn draw() {}

/// contains the loop in which the program runs.
pub fn app_loop(
    stdout: &mut RawTerminal<Stdout>,
    //asy_inp: &mut termion::AsyncReader,
    __data: &Vec<u8>,
) -> Result<Option<Vec<u8>>, io::Error> {
    // Hardcoded bad..
    const XCURSOR: u16 = 1; //48; // Top Left modifiable cell
    const YCURSOR: u16 = 1; // Top line
    let mut reader = io::stdin();

    let mut xcursor = XCURSOR; // Start of the `value` box
    let mut ycursor = YCURSOR; // skip top border line
    let mut data = __data.to_vec();
    let mut osy: u16 = 0; // offset of scrolling vertically
    let mut page_num: u16 = 0;
    let height = terminal_size().unwrap().1;

    let mut addr = get_addr_repr(page_num.into(), (height + page_num).into(), 8);
    //addr[(ycursor - 1) as usize].0[0].style = Style::default().fg(Color::Magenta);
    // Hex value box
    let mut _data = get_data_repr(data.to_vec(), Repr::HEX, 0, 1000);
    //    _data[(ycursor - 1) as usize].0[(xcursor - XCURSOR) as usize].style =
    //       Style::default().fg(Color::Green);
    //// Modifiable ascii box
    let mut _ascii = get_data_repr(data.to_vec(), Repr::ASCII, 0, 1000);
    //// Coloring
    write!(
        stdout,
        "{}{}",
        // Clear the screen.
        termion::clear::All,
        // Goto (1,1).
        termion::cursor::Goto(1, 1),
        // Hide the cursor.
    )
    .unwrap();
    // Flush stdout (i.e. make the output appear).

    for i in 0..addr.len() - 1 {
        write!(stdout, "{}\n\r", addr[&i]);
    }
    write!(stdout, "{}", termion::cursor::Goto(xcursor, ycursor)).unwrap();
    stdout.flush().unwrap();

    let mut bytes = reader.bytes();
    loop {
        let b = bytes.next().unwrap().unwrap();
        match b {
            // Clearing the terminal
            b'q' => {
                termion::cursor::Goto(1, 1);
                term_clear(stdout).unwrap();
                write!(stdout, "{}", termion::cursor::Goto(xcursor, ycursor)).unwrap();
                return Ok(Some(data));
            }

            // Navigation Keys
            b'l' => {
                xcursor += 1;
                if xcursor >= XCURSOR + 15 {
                    // Constraint -3 from border lines and 0 indexing
                    continue;
                }
                write!(stdout, "{}", termion::cursor::Goto(xcursor, ycursor)).unwrap();
            }
            b'h' => {
                if xcursor <= XCURSOR {
                    continue;
                }
                xcursor -= 1;
                write!(stdout, "{}", termion::cursor::Goto(xcursor, ycursor)).unwrap();
            }
            b'j' => {
                if ycursor >= height + 1 {
                    continue;
                }
                ycursor += 1;
                write!(stdout, "{}", termion::cursor::Goto(xcursor, ycursor)).unwrap();
            }
            b'k' => {
                if ycursor <= 1 {
                    continue;
                }
                ycursor -= 1;
                write!(stdout, "{}", termion::cursor::Goto(xcursor, ycursor));
            }
            b'g' => {
                xcursor = XCURSOR;
                ycursor = 1;
                write!(stdout, "{}", termion::cursor::Goto(1, 1)).unwrap();
            }
            // Next page key
            b'n' => {
                //    if page_num > ((data_len / 0x10) - (box_height as usize)) as u16 {
                //        break;
                //    }
                osy = osy + height; // offset scroll x
                page_num = page_num + height;
                addr = get_addr_repr(page_num.into(), (height + page_num).into(), 8);
                //term.clear()?;
                //thread::sleep(time::Duration::from_millis(100));
                //dbg!((data.len() / 0x10) - 32);
            }

            b'p' => {
                if osy <= 0 || ycursor <= 0 {
                    break;
                };
                osy = osy.checked_sub(height).unwrap_or(0u16);
                page_num = page_num.checked_sub(height).unwrap_or(0u16);
                termion::cursor::Goto(xcursor, ycursor);
            }

            // Mutating Keys
            //            b'c' => {
            //                // Clunky way to block async_input and get character to change under the cursor
            //                let mut b: u8 =
            //                    data[(xcursor - (XCURSOR) + (16 * ((ycursor + page_num) - 1))) as usize] as u8;
            //
            //                thread::sleep(time::Duration::from_millis(500));
            //                while let Some(Ok((_, k))) = asi.by_ref().events_and_raw().next() {
            //                    b = k[0]
            //                }
            //                data[(xcursor - (XCURSOR) + (16 * ((ycursor + page_num) - 1))) as usize] =
            //                    (b as char) as u8;
            //                break;
            //            }
            b's' => {
                term_clear(stdout).unwrap();
                return Ok(Some(data));
            }

            // Throw away keys
            _ => (),
        }
        stdout.flush().unwrap();
    }
    Ok(Some(vec![1]))
}

pub fn new_file() -> Result<Vec<u8>, ()> {
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
        }
    }
}
