use rand::{thread_rng, Rng};
use std::io;
use std::io::Read;
use std::time::Instant;
use termion::{async_stdin, event::Key, input::TermRead, raw::IntoRawMode};
use tui::backend::TermionBackend;
use tui::layout::{Constraint, Direction, Layout};
use tui::style::{Color, Style};
use tui::text::{Spans, Text};
use tui::widgets::{Block, Borders, Paragraph};
use tui::Terminal;

fn main() -> Result<(), io::Error> {
    // Set up terminal output
    let stdout = io::stdout().into_raw_mode()?;
    let backend = TermionBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    // Create a separate thread to poll stdin.
    // This provides non-blocking input support.
    let mut asi = async_stdin();

    // Clear the terminal
    terminal.clear()?;
    loop {
        // Lock the terminal and start a drawing session.
        terminal.draw(|frame| {
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
	    let txt1 = vec![Spans::from("")];
            let graph = Paragraph::new(Text::raw(""))
                // In a block with borders and the given title...
                .block(Block::default().title(" Bytes ").borders(Borders::ALL))
                // With white foreground and black background...
                .style(Style::default().fg(Color::White).bg(Color::Black));

	    frame.render_widget(graph, chunks[1]);
        })?;



        // Iterate over all the keys that have been pressed since the
        // last time we checked.
        for k in asi.by_ref().keys() {
            match k.unwrap() {
                // If any of them is q, quit
                Key::Char('q') => {
                    // Clear the terminal before exit so as not to leave
                    // a mess.
                    terminal.clear()?;
                    return Ok(());
                }
                // Otherwise, throw them away.
                _ => (),
            }
        }
    }
}

// Implementation of a dwarf devourer using gimli lib //
// A simple example of parsing `.debug_info`.

//let buffer = hexi::new_file().unwrap();
//println!("{:?}", buffer);

//use object::{Object, ObjectSection};
//use std::{borrow, env, fs};
//use gimli::AttributeValue;
//
//fn main() {
//    for path in env::args().skip(1) {
//        let file = fs::File::open(&path).unwrap();
//        let mmap = unsafe { memmap::Mmap::map(&file).unwrap() };
//        let object = object::File::parse(&mmap).unwrap();
//        let endian = if object.is_little_endian() {
//            gimli::RunTimeEndian::Little
//        } else {
//            gimli::RunTimeEndian::Big
//        };
//        dump_file(&object, endian).unwrap();
//    }
//}
//
//fn dump_file(object: &object::File, endian: gimli::RunTimeEndian) -> Result<(), gimli::Error>  {
//    // Load a section and return as `Cow<[u8]>`.
//    let load_section = |id: gimli::SectionId| -> Result<borrow::Cow<[u8]>, gimli::Error> {
//        match object.section_by_name(id.name()) {
//            Some(ref section) => Ok(section
//                .uncompressed_data()
//                .unwrap_or(borrow::Cow::Borrowed(&[][..]))),
//            None => Ok(borrow::Cow::Borrowed(&[][..])),
//        }
//    };
//    // Load a supplementary section. We don't have a supplementary object file,
//    // so always return an empty slice.
//    let load_section_sup = |_| Ok(borrow::Cow::Borrowed(&[][..]));
//
//    // Load all of the sections.
//    let dwarf_cow = gimli::Dwarf::load(&load_section, &load_section_sup)?;
//
//    // Borrow a `Cow<[u8]>` to create an `EndianSlice`.
//    let borrow_section: &dyn for<'a> Fn(
//        &'a borrow::Cow<[u8]>,
//    ) -> gimli::EndianSlice<'a, gimli::RunTimeEndian> =
//        &|section| gimli::EndianSlice::new(&*section, endian);
//
//    // Create `EndianSlice`s for all of the sections.
//    let dwarf = dwarf_cow.borrow(&borrow_section);
//
//    // Iterate over the compilation units.
//    let mut iter = dwarf.units();
//    while let Some(header) = iter.next()? {
////        println!(
////            "Unit at <.debug_info+0x{:x}>",
////            header.offset().as_debug_info_offset().unwrap().0
////        );
//        let unit = dwarf.unit(header)?;
//
//        // Iterate over the Debugging Information Entries (DIEs) in the unit.
//        let mut depth = 0;
//        let mut entries = unit.entries();
//	println!("Variables: ");
//        while let Some((delta_depth, entry)) = entries.next_dfs()? {
//           depth += delta_depth;
//           println!("<{}><{:x}> {}", depth, entry.offset().0, entry.tag());
//
//            // Iterate over the attributes in the DIE.
//            let mut attrs = entry.attrs();
//            while let Some(attr) = attrs.next()? {
//		println!("\t{}: {:?}", attr.name(), attr.value());
//                // print!("   {}: ", attr.name());
//		// Transforming to ascii variable
//		match attr.value() {
//		    AttributeValue::String(i) => println!("\t\t{:?}", *i.slice().first().unwrap() as char),
//		    _ => continue,
//		}
//            }
//        }
//    }
//    Ok(())
//}
