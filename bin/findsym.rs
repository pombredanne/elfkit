extern crate elfkit;
extern crate ar;
extern crate bloom;
extern crate rayon;

use std::env;
use elfkit::loader;
use rayon::prelude::*;

fn main() {
    let needle = env::args().nth(1).unwrap().into_bytes();
    let state: Vec<loader::State> = env::args().skip(2).map(|s| loader::State::Path{name:s}).collect();

    let on_error = |e,name| {
        println!("{:?} while loading {}", e, name);
        Vec::with_capacity(0)
    };

    let (_, matches) : (Vec<loader::State>, Vec<loader::State>) =
                            state.into_iter().flat_map(|l| l.load_if(&vec![&needle], &on_error))
                            .partition(|o| if let &loader::State::Object{..} = o {false} else {true});

    println!("{} objects matched", matches.len());
    for ma in matches {
        if let loader::State::Object{name, ..} = ma {
            println!("  - {}", name);
        }
    }
}
