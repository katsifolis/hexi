use cursive::traits::*;
use cursive::views::{Dialog, EditView, TextView};
use cursive::Cursive;

use std::mem;

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}


fn main() {
    let buffer = hexi::new_file().unwrap();
    println!("{:#?}", buffer);


    let mut siv = cursive::default();

    siv.add_global_callback('q', |s| s.quit());
    siv.add_layer(TextView::new("Hello hexi!\n Press <q> to quit."));
    siv.run();
}

