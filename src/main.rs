use hexi::{app_loop, new_file, Binary};
use std::io;
use std::thread;
use std::time;
use termion::async_stdin;
use termion::raw::IntoRawMode;
use termion::cursor::DetectCursorPos;
use tui::backend::TermionBackend;
use tui::Terminal;

fn main() -> Result<(), io::Error> {
    // Retrieve bytes buffer from stdin file
    let binary = Binary {
        name: "hi".to_string(),
        buffer: new_file().unwrap(),
    };
    //    drw_data(binary.buffer);
    //
    //    Ok(())

    // Set up terminal output
    let stdout = io::stdout().into_raw_mode()?;

    let mut backend = TermionBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create a separate thread to poll stdin.
    // This provides non-blocking input support.
    let mut asi = async_stdin();
    // Clear the terminal
    terminal.clear()?;

    match app_loop(&mut terminal, &mut asi, &binary.buffer) {
        Ok(_) => Ok(()),
        Err(err) => Err(err),
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
