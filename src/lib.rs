use std::env;
use std::fs;
use std::io;
use std::io::Read;
use std::process;
use termion::event::Key;
use termion::input::TermRead;
use termion::raw::RawTerminal;
use tui::backend::TermionBackend;
use tui::layout::{Constraint, Direction, Layout, Rect};
use tui::style::{Color, Style};
use tui::terminal;
use tui::text::{Spans, Text}; //use tui::text::{Spans, Text};
use tui::widgets::{Block, Borders, Paragraph};

#[allow(dead_code)]

pub struct Buffer {
    content: Vec<u8>,
}

pub struct Binary {
    pub name: String,     // Name of the file
    pub content: Vec<u8>, // The contents of the binary
    pub arch: String,     // The architecture that was compiled
}

pub fn drw_ui(_data: Vec<u8>) -> Result<(), io::Error> {
    Ok(())
}

pub fn drw_addr(offset: u32, length: u8) -> Vec<u32> {
    let addr_iter: Vec<u32> = (1..offset)
                              .filter(|&x| x == offset)
                              .collect::<Vec<u32>>();
    addr_iter
}

/// contains the loop in which the program runs.
pub fn app_loop(
    term: &mut terminal::Terminal<TermionBackend<RawTerminal<io::Stdout>>>,
    asy_inp: &mut termion::AsyncReader,
) -> Result<(), io::Error> {
    loop {
        // Lock the term and start a drawing session.
        term.draw(|frame| {
            // Create a layout into which to place our blocks.
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [
                        Constraint::Length(10),
                        Constraint::Min(10),
                        Constraint::Min(10),
                    ]
                    .as_ref(),
                )
                .split(frame.size());

            let addr = vec![
                Spans::from("00000000"),
                Spans::from("00000010"),
                Spans::from("00000020"),
                Spans::from("00000030"),
                Spans::from("00000040"),
                Spans::from("00000050"),
                Spans::from("00000060"),
                Spans::from("00000070"),
                Spans::from("00000080"),
                Spans::from("00000090"),
                Spans::from("000000A0"),
            ];

            let graph = Paragraph::new(addr)
                // In a block with borders and the given title...
                .block(Block::default().title(" Address ").borders(Borders::ALL))
                // With white foreground and black background...
                .style(Style::default().fg(Color::White).bg(Color::Black));

            // Fill the address box.

            // Render into the second chunk of the layout.
            frame.render_widget(graph, chunks[0]);
            let graph = Paragraph::new(Text::raw(""))
                // In a block with borders and the given title...
                .block(Block::default().title(" Bytes ").borders(Borders::ALL))
                // With white foreground and black background...
                .style(Style::default().fg(Color::White).bg(Color::Black));

            frame.render_widget(graph, chunks[1]);

            let graph = Paragraph::new(Text::raw(""))
                // In a block with borders and the given title...
                .block(Block::default().title(" Value ").borders(Borders::ALL))
                // With white foreground and black background...
                .style(Style::default().fg(Color::White).bg(Color::Black));

            frame.render_widget(graph, chunks[2]);
        })?;

        // Iterate over all the keys that have been pressed since the
        // last time we checked.
        for k in asy_inp.by_ref().keys() {
            match k.unwrap() {
                // If any of them is q, quit
                Key::Char('q') => {
                    // Clear the term before exit so as not to leave
                    // a mess.
                    term.clear()?;
                    return Ok(());
                }
                // Otherwise, throw them away.
                _ => (),
            }
        }
    }
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
        }
    }
}
