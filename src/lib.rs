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
/// Number Represantation at various bases
pub enum Repr {
    BINARY,
    OCTAL,
    DECIMAL,
    HEX,
    ASCII,
}

/// returns with default values they byte representation of the file
/// in cols of 5 and in rows of <file_size/5>
pub fn get_data_repr<'a>(_data: Vec<u8>, format: Repr, col: usize, row: usize) -> Vec<Spans<'a>> {
    let mut values = Vec::<Spans>::new();
    let mut tmp = String::from("");
    for (idx, v) in _data.iter().enumerate() {
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
            let subs = tmp
                .as_bytes()
                .chunks(2)
                .map(|s| unsafe { ::std::str::from_utf8_unchecked(s) })
                .collect::<Vec<_>>();

            let res: Vec<String> = subs.iter().map(|s| s.to_string()).collect();
            let v: Vec<Span<'a>> = res.into_iter().map(|s| Span::from(s)).collect();
            values.push(Spans::from(v));
            tmp.clear();
            //        } else if (idx + 1) % 3 == 0 && format == Repr::HEX {
            //            tmp.push_str(" ");
        }
        if idx > 0x370 {
            break;
        }
    }
    match format {
        Repr::HEX => values[row].0[col].style = Style::default().fg(Color::Red),
        _ => (),
    }

    values
}

/// returns a string representation of address in hex format with offset from
/// 0 and length of the number
pub fn get_addr_repr<'a>(offset: usize, length: usize, col: usize) -> Vec<Spans<'a>> {
    let mut addr_iter: Vec<Spans> = (0..offset)
        .map(|x| {
            Spans::from(Span::styled(
                format!("{:01$X}", x * 0x10, length),
                Style::default(),
            ))
        }) //.fg(c.unwrap_or(Color::White)).bg(Color::Black))))
        .collect();

    addr_iter[col].0[0].style = Style::default().fg(Color::Magenta);
    addr_iter
}

/// contains the loop in which the program runs.
pub fn app_loop(
    term: &mut terminal::Terminal<TermionBackend<RawTerminal<io::Stdout>>>,
    asy_inp: &mut termion::AsyncReader,
    data: &Vec<u8>,
) -> Result<(), io::Error> {
    const XCURSOR: u16 = 48;
    let mut xcursor = XCURSOR; // Start of the `value` box
    let mut ycursor = 1; // skip top border line
    loop {
        // TODO On resize reset ycursor and xcursor to box_height, box_width values.
        let _box_width = term.size().unwrap().width - 3; // 1 left border, 1 right border
        let box_height = term.size().unwrap().height - 3; // 1 top border, 1 bottom border
        thread::sleep(time::Duration::from_millis(16));
        term.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [
                        Constraint::Length(10), // addresses with padding
                        Constraint::Length(36), // 25 = 2 (2 nibble = byte) * 10 (byte) + 5 (spaces)
                        Constraint::Length(21), // value box
                        Constraint::Length(100),
                    ]
                    .as_ref(),
                )
                .split(frame.size());
            // Address box
            let addr = get_addr_repr(data.len() / 10, 8, (ycursor - 1) as usize);
            let graph = Paragraph::new(addr)
                .block(Block::default().title(" Address ").borders(Borders::ALL))
                .style(Style::default().fg(Color::White).bg(Color::Black));

            frame.render_widget(graph, chunks[0]);

            let _data = get_data_repr(
                data.to_vec(),
                Repr::HEX,
                (xcursor - XCURSOR) as usize,
                (ycursor - 1) as usize,
            );
            let graph = Paragraph::new(_data)
                .alignment(Alignment::Center)
                .block(Block::default().title(" Bytes ").borders(Borders::ALL))
                .style(Style::default().fg(Color::White).bg(Color::Black));

            frame.render_widget(graph, chunks[1]);

            let _ascii = get_data_repr(
                data.to_vec(),
                Repr::ASCII,
                (xcursor - XCURSOR) as usize,
                (ycursor - 1) as usize,
            );
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
                    if xcursor >= XCURSOR + 15 {
                        // Constraint -3 from border lines and 0 indexing
                        break;
                    }
                    xcursor += 1;
                }
                Key::Char('h') => {
                    if xcursor <= XCURSOR {
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
                    xcursor = XCURSOR;
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
