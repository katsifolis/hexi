use std::env;
use std::fs;
use std::io;
use std::io::Read;
use std::process;
use std::thread;
use std::time;
use termion::event::Key;
use termion::input::TermRead;
use termion::raw::RawTerminal;
use tui::backend::TermionBackend;
use tui::layout::{Alignment, Constraint, Direction, Layout};
use tui::style::{Color, Style};
use tui::terminal;
use tui::text::{Span, Spans};
use tui::widgets::{Block, Borders, Paragraph};

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
pub enum Repr {
    BINARY,
    OCTAL,
    DECIMAL,
    HEX,
    ASCII,
}

/// returns with default values they byte representation of the file
/// in cols of 5 and in rows of <file_size/5>
pub fn get_data_repr<'a>(_data: Vec<u8>, format: Repr) -> Vec<Spans<'a>> {
    let mut values = Vec::<Spans>::new();
    let mut tmp = String::from("");
    for (idx, v) in _data.iter().enumerate() {
        if (idx + 1) % 15 == 0 {
            tmp.push_str("\n");
            values.push(Spans::from(Span::styled(
                tmp.clone(),
                Style::default().fg(Color::White).bg(Color::Black),
            )));
            tmp.clear();
        } else if (idx + 1) % 3 == 0 && format == Repr::HEX {
            tmp.push_str(" ");
        } else {
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
        }

        if idx > 0x370 {
            break;
        }
    }
    values
}

/// returns a string representation of address in hex format with offset from
/// 0 and length of the number
pub fn get_addr_repr<'a>(offset: usize, length: usize) -> Vec<Spans<'a>> {
    let addr_iter: Vec<Spans> = (0..offset)
        .map(|x| Spans::from(format!("{:01$X}", x * 0x10, length))) //.fg(c.unwrap_or(Color::White)).bg(Color::Black))))
        .collect();
    addr_iter
}

/// contains the loop in which the program runs.
pub fn app_loop(
    term: &mut terminal::Terminal<TermionBackend<RawTerminal<io::Stdout>>>,
    asy_inp: &mut termion::AsyncReader,
    data: &Vec<u8>,
) -> Result<(), io::Error> {
    // Lock the term and start a drawing session.
    let mut xcursor = 36; // Start of the `value` box
    let mut ycursor = 1; // skip top border line
                         //    let mut mod_color = Color::White;
                         //    let mut mod_modif = Modifier::SLOW_BLINK;

    loop {
        // TODO On resize reset ycursor and xcursor to box_height, box_width values.

        let _box_width = term.size().unwrap().height - 3; // 1 left border, 1 right border
        let box_height = term.size().unwrap().height - 3; // 1 top border, 1 bottom border
        thread::sleep(time::Duration::from_millis(16));
        term.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [
                        Constraint::Length(10), // addresses with padding
                        Constraint::Length(25), // 25 = 2 (2 nibble = byte) * 10 (byte) + 5 (spaces)
                        Constraint::Length(15),
                        Constraint::Length(100),
                    ]
                    .as_ref(),
                )
                .split(frame.size());
            // Address box
            let addr = get_addr_repr(data.len() / 10, 8);
            let graph = Paragraph::new(addr)
                .alignment(Alignment::Center)
                .block(Block::default().title(" Address ").borders(Borders::ALL))
                .style(Style::default().fg(Color::White).bg(Color::Black));

            frame.render_widget(graph, chunks[0]);

            let _data = get_data_repr(data.to_vec(), Repr::HEX);
            //            println!("{:?}", _data[1].0[0].content.chars().nth(1).unwrap());
            let graph = Paragraph::new(_data)
                .alignment(Alignment::Center)
                .block(Block::default().title(" Bytes ").borders(Borders::ALL))
                .style(Style::default().fg(Color::White).bg(Color::Black));

            frame.render_widget(graph, chunks[1]);

            let _ascii = get_data_repr(data.to_vec(), Repr::ASCII);
            let graph = Paragraph::new(_ascii)
                .alignment(Alignment::Center)
                .block(Block::default().title(" Value ").borders(Borders::ALL))
                .style(Style::default().fg(Color::White).bg(Color::Black));

            frame.render_widget(graph, chunks[2]);
            frame.set_cursor(xcursor, ycursor);
        })?;

        for k in asy_inp.by_ref().keys() {
            match k.unwrap() {
                // Misc

                // Clearing the terminal
                Key::Char('q') => {
                    term.clear()?;
                    return Ok(());
                }

                // Navigation Keys
                Key::Char('l') => {
                    if xcursor >= 48 {
                        break;
                    }
                    xcursor += 1;
                }
                Key::Char('h') => {
                    if xcursor <= 36 {
                        break;
                    }
                    xcursor -= 1;
                }
                Key::Char('j') => {
                    if ycursor >= box_height + 1 {
                        break;
                    }
                    ycursor += 1;
                }
                Key::Char('k') => {
                    if ycursor <= 1 {
                        break;
                    }
                    ycursor -= 1;
                }
                Key::Char('g') => {
                    xcursor = 36;
                    ycursor = 1;
                }

                // Mutating Keys
                Key::Char('c') => {}

                // Throw away keys
                _ => (),
            }
        }
    }
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
