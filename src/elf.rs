use header::Header;
use types;
use error::Error;
use section::*;
use segment::*;
use symbol;
use section;

use ordermap::{OrderMap};
use std::collections::hash_map::{self,HashMap};
use std::io::{Read, Seek, SeekFrom, Write};
use std;
use std::iter::FromIterator;

#[derive(Default)]
pub struct Elf {
    pub header: Header,
    pub segments: Vec<SegmentHeader>,
    pub sections: Vec<Section>,
}

impl Elf {
    pub fn from_header(header: Header) -> Self {
        Self {
            header:     header,
            segments:   Vec::new(),
            sections:   Vec::new(),
        }
    }

    pub fn from_reader<R>(io: &mut R) -> Result<Elf, Error>
    where
        R: Read + Seek,
    {
        let header = Header::from_reader(io)?;

        // parse segments
        let mut segments = Vec::with_capacity(header.phnum as usize);
        io.seek(SeekFrom::Start(header.phoff))?;
        let mut buf = vec![0; header.phentsize as usize * header.phnum as usize];
        {
            io.read_exact(&mut buf)?;
            let mut bio = buf.as_slice();
            for _ in 0..header.phnum {
                let segment = SegmentHeader::from_reader(&mut bio, &header)?;
                segments.push(segment);
            }
        }

        // parse section headers
        let mut sections = Vec::with_capacity(header.shnum as usize);
        io.seek(SeekFrom::Start(header.shoff))?;
        buf.resize(header.shnum as usize * header.shentsize as usize,0);
        {
            io.read_exact(&mut buf)?;
            let mut bio = buf.as_slice();
            for _ in 0..header.shnum {
                let sh = SectionHeader::from_reader(&mut bio, &header)?;

                sections.push(Section{
                    name:       Vec::with_capacity(0),
                    content:    SectionContent::Unloaded,
                    header:     sh,
                });
            }
        }

        // resolve section names
        let shstrtab = match sections.get(header.shstrndx as usize) {
            None => return Err(Error::MissingShstrtabSection),
            Some(sec) => {
                io.seek(SeekFrom::Start(sec.header.offset))?;
                let mut shstrtab = vec![0;sec.header.size as usize];
                io.read_exact(&mut shstrtab)?;
                shstrtab
            },
        };

        for ref mut sec in &mut sections {
            sec.name = shstrtab[sec.header.name as usize..]
                .split(|e| *e == 0)
                .next()
                .unwrap_or(&[0; 0])
                .to_vec();
        }

        Ok(Elf{
            header:     header,
            segments:   segments,
            sections:   sections,
        })
    }

    pub fn load<R> (&mut self, i: usize, io: &mut R) -> Result<(), Error>
        where
        R: Read + Seek,
    {
        let mut sec = std::mem::replace(&mut self.sections[i], Section::default());
        {
            let link = sec.header.link.clone();
            let linked = {
                if link < 1 || link as usize >= self.sections.len() {
                    None
                } else {
                    self.load(link as usize, io)?;
                    Some(&self.sections[link as usize])
                }
            };
            sec.from_reader(io, linked, &self.header)?;
        }
        self.sections[i] = sec;

        Ok(())
    }

    pub fn load_all<R> (&mut self, io: &mut R) -> Result<(), Error>
        where
        R: Read + Seek,
    {
        for i in 0..self.sections.len() {
            self.load(i, io)?;
        }
        Ok(())
    }

    /// write out everything to linked sections, such as string tables
    /// after calling this function, size() is reliable for all sections
    pub fn sync_all(&mut self) -> Result<(), Error> {
        match self.sections.iter().position(|s| s.name == b".shstrtab") {
            Some(i) => {
                self.header.shstrndx = i as u16;
                let mut shstrtab = std::mem::replace(
                    &mut self.sections[self.header.shstrndx as usize].content,
                    SectionContent::default(),
                );

                for sec in &mut self.sections {
                    sec.header.name = shstrtab
                        .as_strtab_mut()
                        .unwrap()
                        .insert(&sec.name)
                        as u32;
                }
                self.sections[self.header.shstrndx as usize].content = shstrtab;
            }
            None => {}
        };


        let mut dirty: Vec<usize> = (0..self.sections.len()).collect();
        while dirty.len() > 0 {
            for i in std::mem::replace(&mut dirty, Vec::new()).iter() {
                //work around the borrow checker
                let mut sec = std::mem::replace(&mut self.sections[*i], Section::default());
                {
                    let linked = {
                        if sec.header.link < 1 || sec.header.link as usize >= self.sections.len() {
                            None
                        } else {
                            dirty.push(sec.header.link as usize);
                            Some(&mut self.sections[sec.header.link as usize].content)
                        }
                    };
                    sec.sync(&self.header, linked)?;
                }

                //put it back in
                self.sections[*i] = sec;
            }
        }

        Ok(())
    }

    pub fn to_writer<R>(&mut self, mut io: R) -> Result<(), Error>
    where
        R: Write + Seek,
    {
        io.seek(SeekFrom::Start(0))?;
        let off = self.header.size();
        io.write(&vec![0; off])?;

        // segment headers
        // MUST be written before section content, because it MUST be in the first LOAD
        // otherwise the kernel passes an invalid aux vector
        if self.segments.len() > 0 {
            self.header.phoff = off as u64;
            for seg in &self.segments {
                seg.to_writer(&self.header, &mut io)?;
            }
            let at = io.seek(SeekFrom::Current(0))? as usize;
            self.header.phnum = self.segments.len() as u16;
            self.header.phentsize = ((at - off) / self.segments.len()) as u16;
        }

        let headers: Vec<SectionHeader> = self.sections.iter().map(|s| s.header.clone()).collect();
        let mut sections = std::mem::replace(&mut self.sections, Vec::new());

        //sections
        sections.sort_unstable_by(|a, b| a.header.offset.cmp(&b.header.offset));
        for sec in sections {
            assert_eq!(
                io.seek(SeekFrom::Start(sec.header.offset))?,
                sec.header.offset
            );

            sec.to_writer(&mut io, &self.header)?;
        }


        //section headers
        if self.header.shstrndx > 0 {
            let off = io.seek(SeekFrom::End(0))? as usize;
            self.header.shoff = off as u64;
            for sec in &headers {
                sec.to_writer(&self.header, &mut io)?;
            }
            self.header.shnum = headers.len() as u16;
            self.header.shentsize = SectionHeader::entsize(&self.header) as u16;
        }

        //hygene
        self.header.ehsize = self.header.size() as u16;

        io.seek(SeekFrom::Start(0))?;
        self.header.to_writer(&mut io)?;

        Ok(())
    }

    ///gnu ld compatibility. this is very inefficent,
    ///but not doing this might break some GNU tools that rely on specific gnu-ld behaviour
    /// - reorder symbols to have GLOBAL last
    /// - remove original SECTION symbols and add offset to reloc addend instead
    /// - insert new symbol sections on the top
    pub fn make_symtab_gnuld_compat(&mut self) {
        for i in 0..self.sections.len() {
            if self.sections[i].header.shtype == types::SectionType::SYMTAB {
                self._make_symtab_gnuld_compat(i);
            }
        }
        self.sync_all();
    }

    fn _make_symtab_gnuld_compat(&mut self, shndx: usize) {

        let mut original_size = self.sections[shndx].content.as_symbols().unwrap().len();

        let mut symtab_sec = HashMap::new();
        //I = new index
        //V.0 = old index
        //V.1 = sym
        let mut symtab_remap = Vec::new();
        for (i, link)  in self.sections[shndx].content.as_symbols_mut().unwrap().drain(..).enumerate() {
            if link.stype == types::SymbolType::SECTION {
                symtab_sec.insert(i, link);
            } else {
                symtab_remap.push((i, link));
            }
        }

        let mut symtab_gs = Vec::new();
        let mut symtab_ls = Vec::new();
        for (oi,mut sym) in symtab_remap {
            if sym.bind == types::SymbolBind::GLOBAL {
                symtab_gs.push((oi, sym));
            } else {
                symtab_ls.push((oi, sym));
            }
        }
        symtab_gs.sort_unstable_by(|a,b|{
            a.1.value.cmp(&b.1.value)
        });


        symtab_ls.insert(0, (original_size, symbol::Symbol::default()));
        original_size += 1;

        let mut nu_sec_syms = vec![0];
        for i in 1..self.sections.len() {
            symtab_ls.insert(i, (original_size, symbol::Symbol{
                shndx:  symbol::SymbolSectionIndex::Section(i as u16),
                value:  0,
                size:   0,
                name:   Vec::new(),
                stype:  types::SymbolType::SECTION,
                bind:   types::SymbolBind::LOCAL,
                vis:    types::SymbolVis::DEFAULT,
                _name:  0,
            }));
            nu_sec_syms.push(original_size);
            original_size += 1;
        }

        symtab_ls.push((original_size, symbol::Symbol{
            shndx:  symbol::SymbolSectionIndex::Absolute,
            value:  0,
            size:   0,
            name:   Vec::new(),
            stype:  types::SymbolType::FILE,
            bind:   types::SymbolBind::LOCAL,
            vis:    types::SymbolVis::DEFAULT,
            _name:  0,
        }));
        original_size += 1;


        let mut symtab_remap : OrderMap<usize, symbol::Symbol>
            = OrderMap::from_iter(symtab_ls.into_iter().chain(symtab_gs.into_iter()));

        for sec in &mut self.sections {
            match sec.header.shtype {
                types::SectionType::RELA => {
                    if sec.header.link != shndx as u32{
                        continue;
                    }
                    for reloc in sec.content.as_relocations_mut().unwrap().iter_mut() {
                        if let Some(secsym) = symtab_sec.get(&(reloc.sym as usize)) {
                            if let symbol::SymbolSectionIndex::Section(so) = secsym.shndx {
                                reloc.addend += secsym.value as i64;
                                reloc.sym     = nu_sec_syms[so as usize] as u32;
                            } else {
                                unreachable!();
                            }
                        }

                        reloc.sym = symtab_remap.get_full(&(reloc.sym as usize))
                            .expect("bug in elfkit: dangling reloc").0 as u32;
                    }
                },
                _ => {},
            }
        }

        self.sections[shndx].content = section::SectionContent::Symbols(
            symtab_remap.into_iter().map(|(k,v)|v).collect());
    }



    //TODO this code isnt tested at all
    //TODO the warnings need to be emited when calling store_all instead
    pub fn remove_section(&mut self, at: usize) -> Result<(Section), Error> {
        let r = self.sections.remove(at);

        for sec in &mut self.sections {
            if sec.header.link == at as u32 {
                sec.header.link = 0;
            //println!("warning: removed section {} has a dangling link from {}", at, sec.name);
            } else if sec.header.link > at as u32 {
                sec.header.link -= 1;
            }

            if sec.header.flags.contains(types::SectionFlags::INFO_LINK) {
                if sec.header.info == at as u32 {
                    sec.header.info = 0;
                //println!("warning: removed section {} has a dangling info link from {}", at,
                //sec.name);
                } else if sec.header.info > at as u32 {
                    sec.header.info -= 1;
                }
            }
        }

        Ok((r))
    }
    pub fn insert_section(&mut self, at: usize, sec: Section) -> Result<(), Error> {
        self.sections.insert(at, sec);

        for sec in &mut self.sections {
            if sec.header.link >= at as u32 {
                sec.header.link += 1;
            }

            if sec.header.flags.contains(types::SectionFlags::INFO_LINK) {
                if sec.header.info > at as u32 {
                    sec.header.info += 1;
                }
            }
        }

        Ok(())
    }

    pub fn move_section(&mut self, from: usize, mut to: usize) -> Result<(), Error> {
        if to == from {
            return Ok(());
        }
        if to > from {
            to -= 1;
        }


        for sec in &mut self.sections {
            if sec.header.link == from as u32 {
                sec.header.link = 999999;
            }
            if sec.header.flags.contains(types::SectionFlags::INFO_LINK) {
                if sec.header.info == from as u32 {
                    sec.header.info = 999999;
                }
            }
        }
        let sec = self.remove_section(from)?;
        self.insert_section(to, sec)?;
        for sec in &mut self.sections {
            if sec.header.link == 999999 {
                sec.header.link = to as u32;
            }
            if sec.header.flags.contains(types::SectionFlags::INFO_LINK) {
                if sec.header.info == 999999 {
                    sec.header.info = to as u32;
                }
            }
        }

        Ok(())
    }
}
