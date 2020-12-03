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
use tui::layout::{Constraint, Direction, Layout};
use tui::style::{Color, Style};
use tui::terminal;
use tui::text::{Spans, Text}; //use tui::text::{Spans, Text};
use tui::widgets::{Block, Borders, Paragraph};

#[allow(dead_code)]

pub struct Binary {
    pub name: String,    // Name of the file
    pub buffer: Vec<u8>, // The contents of the binary
}

pub fn drw_data<'a>(_data: Vec<u8>) -> Vec<Spans<'a>> {
    let mut values = Vec::<Spans>::new();
    let mut tmp = String::from("");
    for (idx , v ) in _data.iter().enumerate() {
        if (idx+1) % 15 == 0 {
            tmp.push_str("\n");
            values.push(Spans::from(tmp.clone()));
            tmp.clear();
//           println!("{}", tmp);
//          
        } else if (idx+1) % 3 == 0 {
            tmp.push_str(" ");
            
        } else {
            tmp.push_str(&*String::from(format!("{:02x}", v))) // passing the values;
        }

        if idx > 0xF0 { break; }
    }
    values
}

/// returns a string representation of address in hex format with offset from
/// 0 and length of the number
pub fn drw_addr<'a>(offset: u32, length: usize) -> Vec<Spans<'a>> {
    let addr_iter: Vec<Spans> = (0..offset)
        .map(|x| Spans::from(format!("{:01$X}", x * 0x10, length)))
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
    loop {
        thread::sleep(time::Duration::from_millis(100)); //
        term.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [
                        Constraint::Length(10), // addresses with padding
                        Constraint::Length(25), // 25 = 2 (2 nibble = byte) * 10 (byte) + 5 (spaces)
                        Constraint::Max(20),
                    ]
                    .as_ref(),
                )
                .split(frame.size());

            // Address box
            let addr = drw_addr(16, 8);
            let graph = Paragraph::new(addr)
                .block(Block::default().title(" Address ").borders(Borders::ALL))
                .style(Style::default().fg(Color::White).bg(Color::Black));

            frame.render_widget(graph, chunks[0]);

            let _data = drw_data(data.to_vec());
            let graph = Paragraph::new(_data)
                .block(Block::default().title(" Bytes ").borders(Borders::ALL))
                .style(Style::default().fg(Color::White).bg(Color::Black));

            frame.render_widget(graph, chunks[1]);

            let graph = Paragraph::new(Text::raw(""))
                .block(Block::default().title(" Value ").borders(Borders::ALL))
                .style(Style::default().fg(Color::White).bg(Color::Black));

            frame.render_widget(graph, chunks[2]);
            frame.set_cursor(10, 100);
        })?;

        for k in asy_inp.by_ref().keys() {
            match k.unwrap() {
                Key::Char('q') => {
                    // Clearing the terminal
                    term.clear()?;
                    return Ok(());
                }
                Key::Char('l') => {
                    term.set_cursor(11, 10);
                }
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
