extern crate elfkit;
extern crate ar;
extern crate bloom;

use std::env;
use elfkit::loader::{self, LoadIf};

fn main() {
    let needle = env::args().nth(1).unwrap().into_bytes();
    let state: Vec<loader::State> = env::args().skip(2).map(|s| loader::State::Path{name:s}).collect();

    let (_, matches) = state.load_if(&vec![&needle], &|e,name|{
        println!("{:?} while loading {}", e, name);
        Vec::with_capacity(0)
    });

    println!("{} objects matched", matches.len());
    for ma in matches {
        if let loader::State::Object{name, ..} = ma {
            println!("  - {}", name);
        }
    }
}
