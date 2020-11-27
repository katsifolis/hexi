use std::env;
use std::process;
use std::fs;
use std::io;
use tui::terminal;
use tui::layout::{Constraint, Direction, Layout};
use tui::style::{Color, Style};
use tui::text::Text; //use tui::text::{Spans, Text};
use tui::widgets::{Block, Borders, Paragraph};
use tui::backend::TermionBackend;
use termion::event::Key;
use termion::input::TermRead;
use termion::raw::RawTerminal;
use std::io::Read;


#[allow(dead_code)]
pub struct Buffer {
    content: Vec<u8>,
}

pub struct Binary {
    pub name:    String,    // Name of the file
    pub content: Vec<u8>,   // The contents of the binary
    pub arch:    String,    // The architecture that was compiled
}


pub fn draw_ui (_data: Vec<u8>) -> Result<(), io::Error> {

    Ok(())

}

pub fn app_loop(term: &mut terminal::Terminal<TermionBackend<RawTerminal<io::Stdout>>>, asy_inp: &mut termion::AsyncReader ) -> Result<(), io::Error> {
    loop {
        // Lock the term and start a drawing session.
        term.draw(|frame| {
            // Create a layout into which to place our blocks.
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [
                        Constraint::Percentage(20),
                        Constraint::Percentage(80),
                    ]
                    .as_ref(),
                )
                .split(frame.size());

            // Create a paragraph with the above text...
            let graph = Paragraph::new(Text::raw(""))
                // In a block with borders and the given title...
                .block(Block::default().title(" Address ").borders(Borders::ALL))
                // With white foreground and black background...
                .style(Style::default().fg(Color::White).bg(Color::Black));

            // Render into the second chunk of the layout.
            frame.render_widget(graph, chunks[0]);
            let graph = Paragraph::new(Text::raw(""))
                // In a block with borders and the given title...
                .block(Block::default().title(" Bytes ").borders(Borders::ALL))
                // With white foreground and black background...
                .style(Style::default().fg(Color::White).bg(Color::Black));

	    frame.render_widget(graph, chunks[1]);
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
        },
    }
}
