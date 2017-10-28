extern crate elfkit;
extern crate ordermap;

use std::env;
use elfkit::{Elf, Header, types, symbol, relocation, section, Error, loader, linker, dynamic, segment};
use elfkit::symbolic_linker::{self, SymbolicLinker};
use std::fs::File;
use self::ordermap::{OrderMap};
use std::collections::hash_map::{self,HashMap};
use std::fs::OpenOptions;
use std::io::Write;
use std::iter::FromIterator;
use std::os::unix::fs::PermissionsExt;

fn main() {
    let mut loader: Vec<loader::State> = env::args().skip(1).map(|s| loader::State::Path{name:s}).collect();

    let rootsym = env::args().nth(1).unwrap().into_bytes();
    loader.push(loader::State::Object{
        name:     String::from("___linker_entry"),
        symbols:  vec![symbol::Symbol{
            stype: types::SymbolType::FUNC,
            size:  0,
            value: 0,
            bind:  types::SymbolBind::GLOBAL,
            vis:   types::SymbolVis::DEFAULT,
            shndx: symbol::SymbolSectionIndex::Undefined,
            name:  b"_start".to_vec(),
            _name: 0,
        }],
        header:   Header::default(),
        sections: Vec::new(),
    });

    let mut linker = SymbolicLinker::default();
    linker.link(loader).unwrap();
    println!("lookup complete: {} nodes in link tree", linker.objects.len());
    linker.gc();
    println!("after gc: {}", linker.objects.len());


    let mut elf = Elf::default();

    elf.header.ident_class      = types::Class::Class64;
    elf.header.ident_endianness = types::Endianness::LittleEndian;
    elf.header.ident_abi        = types::Abi::SYSV;
    elf.header.etype            = types::ElfType::DYN;
    elf.header.machine          = types::Machine::X86_64;

    elf.sections.push(section::Section::default());
    elf.sections.push(section::Section::new(b".interp".to_vec(), types::SectionType::PROGBITS,
    types::SectionFlags::ALLOC,
    section::SectionContent::Raw(b"/lib64/ld-linux-x86-64.so.2\0".to_vec()), 0, 0));

    let mut collector = SimpleCollector::new(elf);
    collector.collect(linker);
    let mut elf = collector.into_elf();



    DynamicRelocator::relocate(&mut elf);
    elf.make_symtab_gnuld_compat();
    relayout(&mut elf);
    elf.segments = segments(&elf).unwrap();

    let mut out_file = OpenOptions::new().write(true).truncate(true).create(true).open("/tmp/e").unwrap();
    elf.to_writer(&mut out_file).unwrap();

    let mut perms = out_file.metadata().unwrap().permissions();
    perms.set_mode(0o755);
    out_file.set_permissions(perms).unwrap();
}




/// a dummy implementation of Collector which works for testing
pub struct SimpleCollector {
    elf:        Elf,
    symtab:     Vec<symbol::Symbol>,

    sections:   OrderMap<Vec<u8>, section::Section>,
    relocs:     HashMap<usize, Vec<relocation::Relocation>>,
}

impl SimpleCollector {

    pub fn new(mut elf: Elf) -> SimpleCollector {
        let mut sections = OrderMap::new();
        if elf.sections.len() < 1 {
            sections.insert(Vec::new(), section::Section::default());
        } else {
            for sec in elf.sections.drain(..) {
                sections.insert(sec.name.clone(), sec);
            }
        }

        Self{
            elf:        elf,
            sections:   sections,
            relocs:     HashMap::new(),
            symtab:     Vec::new(),
        }
    }

    fn collect(&mut self, mut linker: SymbolicLinker) {

        let mut input_map = HashMap::new();

        for (_, mut object) in linker.objects {
            let (nu_shndx, nu_off) = self.merge(object.section, object.relocs);
            input_map.insert(object.lid, (nu_shndx, nu_off));
        }

        for loc in &mut linker.symtab {
            match loc.sym.shndx {
                symbol::SymbolSectionIndex::Section(_) => {
                    match input_map.get(&loc.obj) {
                        None => {
                            panic!("linker emitted dangling link {} -> {:?}", loc.obj, loc.sym);
                        },
                        Some(&(nu_shndx, nu_off)) =>  {
                            if let symbol::SymbolSectionIndex::Section(so) = loc.sym.shndx {
                                loc.sym.shndx = symbol::SymbolSectionIndex::Section(nu_shndx as u16);
                                loc.sym.value += nu_off as u64;
                            }
                            self.symtab.push(loc.sym.clone());
                        },
                    };
                },
                symbol::SymbolSectionIndex::Undefined => {
                    self.symtab.push(loc.sym.clone());
                },
                symbol::SymbolSectionIndex::Absolute |
                    symbol::SymbolSectionIndex::Common => {
                    self.symtab.push(loc.sym.clone());
                },
            }
        }

        self.elf.sections = self.sections.drain(..).map(|(k,v)|v).collect();
    }

    pub fn into_elf(mut self) -> Elf {

        let sh_index_strtab = self.elf.sections.len();
        self.elf.sections.push(section::Section::new(b".strtab".to_vec(), types::SectionType::STRTAB,
        types::SectionFlags::empty(),
        section::SectionContent::Strtab(elfkit::strtab::Strtab::default()), 0,0));

        let sh_index_symtab = self.elf.sections.len();
        let first_global_symtab = self.symtab.iter().enumerate()
            .find(|&(_,s)|s.bind == types::SymbolBind::GLOBAL).map(|(i,_)|i).unwrap_or(0);;
        self.elf.sections.push(section::Section::new(b".symtab".to_vec(), types::SectionType::SYMTAB,
        types::SectionFlags::empty(),
        section::SectionContent::Symbols(self.symtab),
        sh_index_strtab as u32, first_global_symtab as u32));

        for (shndx, relocs) in self.relocs {
            let mut name = b".rela".to_vec();
            name.append(&mut self.elf.sections[shndx].name.clone());

            let sh_index_strtab = self.elf.sections.len();
            self.elf.sections.push(section::Section::new(name, types::SectionType::RELA,
            types::SectionFlags::empty(),
            section::SectionContent::Relocations(relocs), sh_index_symtab as u32, shndx as u32));
        }


        self.elf.sections.push(section::Section::new(b".shstrtab".to_vec(), types::SectionType::STRTAB,
        types::SectionFlags::from_bits_truncate(0),
        section::SectionContent::Strtab(elfkit::strtab::Strtab::default()),
        0,0));

        relayout(&mut self.elf);

        self.elf
    }


    fn merge(&mut self, mut sec: section::Section, mut rela: Vec<relocation::Relocation>) -> (usize, usize) {
        let mut name = sec.name.clone();
        if name.len() > 3 && &name[0..4] == b".bss" {
            name = b".bss".to_vec();
        }
        if name.len() > 6 && &name[0..7] == b".rodata" {
            name = b".rodata".to_vec();
        }
        if name.len() > 4 && &name[0..5] == b".data" {
            name = b".data".to_vec();
        }
        if name.len() > 4 && &name[0..5] == b".text" {
            name = b".text".to_vec();
        }
        let (nu_shndx, nu_off) = match self.sections.entry(name.clone()) {
            ordermap::Entry::Occupied(mut e) => {
                let i  = e.index();
                let ov = match sec.content {
                    section::SectionContent::Raw(mut r) => {
                        let align = std::cmp::max(e.get().header.addralign, sec.header.addralign);
                        e.get_mut().header.addralign = align;

                        let cc = e.get_mut().content.as_raw_mut().unwrap();
                        if  cc.len() % align as usize != 0 {
                            let mut al = vec![0;align as usize - (cc.len() % align as usize)];
                            cc.append(&mut al);
                        }
                        let ov = cc.len();
                        cc.append(&mut r);
                        ov
                    },
                    section::SectionContent::None => {
                        let ov = e.get().header.size;
                        e.get_mut().header.size += sec.header.size as u64;
                        ov as usize
                    },
                    _ => unreachable!(),
                };
                (i, ov)
            },
            ordermap::Entry::Vacant(e) => {
                let i = e.index();
                sec.name = name.clone();
                e.insert(sec);
                (i, 0)
            },
        };

        self.relocs.entry(nu_shndx).or_insert_with(||Vec::new()).append(&mut rela);

        (nu_shndx, nu_off)
    }

}




pub fn relayout(elf: &mut Elf) -> Result<(), Error> {
    elf.sync_all()?;
    let mut poff = 0x300;
    let mut voff = 0x300;

    for sec in &mut elf.sections[1..] {
        if sec.header.addralign > 0 {
            let oa = poff % sec.header.addralign;
            if oa != 0 {
                poff += sec.header.addralign - oa;
                voff += sec.header.addralign - oa;
            }
        }
        if sec.header.shtype != types::SectionType::NOBITS {
            if poff > voff {
                panic!("elfkit: relayout: poff>voff 0x{:x}>0x{:x} in {}.", poff, voff,
                       String::from_utf8_lossy(&sec.name));
            }
            if (voff - poff) % 0x200000 != 0 {
                voff += 0x200000 - ((voff - poff) % 0x200000)
            }
        }
        sec.header.offset = poff;
        poff += sec.size(&elf.header) as u64;

        sec.header.addr = voff;
        voff += sec.header.size;
    }

    Ok(())
}





struct DynamicRelocator {
}
impl DynamicRelocator {
    pub fn relocate (elf: &mut Elf) -> Result<(), Error>  {

        let mut dynrel = Vec::new();
        let mut dynsym = vec![symbol::Symbol::default()];
        let mut shndx_dynstr = None;
        let mut last_alloc_shndx = 0;
        let mut delete_secs = Vec::new();

        for i in 0..elf.sections.len() {

            if elf.sections[i].header.flags.contains(types::SectionFlags::ALLOC) {
                last_alloc_shndx = i;
            }

            match elf.sections[i].header.shtype {
                types::SectionType::STRTAB => {
                    if elf.sections[i].name == b".dynstr" {
                        shndx_dynstr = Some(i);
                    }
                },
                types::SectionType::SYMTAB => {
                    let mut symtab = std::mem::replace(&mut elf.sections[i], section::Section::default());

                    for sym in symtab.content.as_symbols_mut().unwrap().iter_mut() {
                        if let symbol::SymbolSectionIndex::Section(so) = sym.shndx {
                            let addr = elf.sections[so as usize].header.addr;
                            sym.value += addr;
                            if sym.name == b"_start" && sym.bind == types::SymbolBind::GLOBAL {
                                elf.header.entry = sym.value;
                            }
                        }
                    }

                    elf.sections[i] = symtab;
                },
                types::SectionType::RELA => {
                    let relocs  = std::mem::replace(&mut elf.sections[i], section::Section::default());
                    delete_secs.insert(0, i);

                    elf.sections[relocs.header.info as usize].header.flags.insert(types::SectionFlags::WRITE);
                    let secaddr = elf.sections[relocs.header.info as usize].header.addr;
                    let symtab  = elf.sections[relocs.header.link as usize].content.as_symbols().unwrap();

                    for mut reloc in relocs.content.into_relocations().unwrap().into_iter() {
                        let sym     = &symtab[reloc.sym as usize];
                        match reloc.rtype {
                            relocation::RelocationType::R_X86_64_64 => {
                                reloc.sym  = 0;
                                reloc.addr += secaddr;
                                reloc.addend += sym.value as i64;
                                dynrel.push(reloc);
                            },
                            _ => {
                                panic!("elfkit::StaticRelocator relocation not implemented {:?}", reloc);
                            }
                        }
                    }
                },
                _=> {},
            }
        }

        for i in delete_secs {
            assert!(i > last_alloc_shndx,
                    "DynamicRelocator only works for rela sections AFTER the last alloc section");
            elf.sections.remove(i);
        }

        if shndx_dynstr == None {
            last_alloc_shndx += 1;
            shndx_dynstr = Some(last_alloc_shndx);

            elf.sections.insert(last_alloc_shndx, section::Section::new(b".dynstr".to_vec(),
            types::SectionType::STRTAB, types::SectionFlags::ALLOC,
            section::SectionContent::Strtab(elfkit::strtab::Strtab::default()), 0, 0));
        }

        last_alloc_shndx += 1;
        let hash = symbol::symhash(&elf.header, &dynsym, last_alloc_shndx as u32 + 1 )?;
        elf.sections.insert(last_alloc_shndx, hash);


        last_alloc_shndx += 1;
        let shndx_dynsym = last_alloc_shndx;
        let first_global_symtab = dynsym.iter().enumerate()
            .find(|&(_,s)|s.bind == types::SymbolBind::GLOBAL).map(|(i,_)|i).unwrap_or(0);;

        elf.sections.insert(shndx_dynsym, section::Section::new(b".dynsym".to_vec(),
        types::SectionType::DYNSYM, types::SectionFlags::ALLOC,
        section::SectionContent::Symbols(dynsym),
        shndx_dynstr.unwrap() as u32, first_global_symtab as u32));


        last_alloc_shndx += 1;
        elf.sections.insert(last_alloc_shndx, section::Section::new(b".rela.dyn".to_vec(),
        types::SectionType::RELA, types::SectionFlags::ALLOC,
        section::SectionContent::Relocations(dynrel),
        shndx_dynsym as u32, 0));

        relayout(elf);

        last_alloc_shndx += 1;
        let dynamic = DynamicRelocator::dynamic(elf)?;
        elf.sections.insert(last_alloc_shndx, section::Section::new(b".dynamic".to_vec(), types::SectionType::DYNAMIC,
        types::SectionFlags::ALLOC | types::SectionFlags::WRITE,
        section::SectionContent::Dynamic(dynamic), shndx_dynstr.unwrap() as u32,0));

        Ok(())

    }

    pub fn dynamic(elf: &Elf) -> Result<Vec<dynamic::Dynamic>, Error> {
        let mut r = vec![
            dynamic::Dynamic{
                dhtype: types::DynamicType::FLAGS_1,
                content: dynamic::DynamicContent::Flags1(types::DynamicFlags1::PIE),
            },
        ];

        for sec in &elf.sections {
            match sec.name.as_slice() {
                b".hash" => {
                    r.push(dynamic::Dynamic {
                        dhtype: types::DynamicType::HASH,
                        content: dynamic::DynamicContent::Address(sec.header.addr),
                    });
                }
                b".dynstr" => {
                    r.push(dynamic::Dynamic {
                        dhtype: types::DynamicType::STRTAB,
                        content: dynamic::DynamicContent::Address(sec.header.addr),
                    });

                    r.push(dynamic::Dynamic {
                        dhtype: types::DynamicType::STRSZ,
                        content: dynamic::DynamicContent::Address(sec.header.size),
                    });
                }
                b".dynsym" => {
                    r.push(dynamic::Dynamic {
                        dhtype: types::DynamicType::SYMTAB,
                        content: dynamic::DynamicContent::Address(sec.header.addr),
                    });
                    r.push(dynamic::Dynamic {
                        dhtype: types::DynamicType::SYMENT,
                        content: dynamic::DynamicContent::Address(sec.header.entsize),
                    });
                }
                b".rela.dyn" => {
                    r.push(dynamic::Dynamic {
                        dhtype: types::DynamicType::RELA,
                        content:dynamic:: DynamicContent::Address(sec.header.addr),
                    });
                    r.push(dynamic::Dynamic {
                        dhtype: types::DynamicType::RELASZ,
                        content: dynamic::DynamicContent::Address(sec.header.size),
                    });
                    r.push(dynamic::Dynamic {
                        dhtype: types::DynamicType::RELAENT,
                        content: dynamic::DynamicContent::Address(sec.header.entsize),
                    });

                    let first_non_rela = match sec.content.as_relocations() {
                        None => return Err(Error::UnexpectedSectionContent),
                        Some(v) => v.iter()
                            .position(|ref r| {
                                r.rtype != relocation::RelocationType::R_X86_64_RELATIVE
                                    && r.rtype != relocation::RelocationType::R_X86_64_JUMP_SLOT
                            })
                        .unwrap_or(v.len()),
                    } as u64;


                    if first_non_rela > 0 {
                        r.push(dynamic::Dynamic {
                            dhtype: types::DynamicType::RELACOUNT,
                            content: dynamic::DynamicContent::Address(first_non_rela),
                        });
                    }

                    if first_non_rela < sec.content.as_relocations().unwrap().len() as u64 {
                        r.push(dynamic::Dynamic {
                            dhtype: types::DynamicType::TEXTREL,
                            content: dynamic::DynamicContent::Address(first_non_rela),
                        });
                    }
                }
                _ => {}
            }
        }

        r.push(dynamic::Dynamic {
            dhtype: types::DynamicType::NULL,
            content: dynamic::DynamicContent::Address(0),
        });
        Ok(r)
    }
}



/// generate program headers from fully layouted sections.
/// sections must be synced
pub fn segments(elf: &Elf) -> Result<Vec<segment::SegmentHeader>, Error> {
    let mut r = Vec::new();
    if elf.sections.len() < 2 {
        return Ok(r);
    }

    let mut vshift = 0 as i64;
    let mut voff = elf.sections[1].header.addr;
    let mut poff = elf.sections[1].header.offset;
    let mut vstart = 0;
    let mut pstart = 0;
    let mut flags = types::SegmentFlags::READABLE;

    for i in 0..elf.sections.len() {
        let section = &elf.sections[i];

        match section.name.as_slice() {
            b".dynamic" => {
                r.push(segment::SegmentHeader {
                    phtype: types::SegmentType::DYNAMIC,
                    flags: types::SegmentFlags::READABLE | types::SegmentFlags::WRITABLE,
                    offset: section.header.offset,
                    filesz: section.header.size,
                    vaddr: section.header.addr,
                    paddr: section.header.addr,
                    memsz: section.header.size,
                    align: 0x8,
                });
            }
            b".interp" => {
                r.push(segment::SegmentHeader {
                    phtype: types::SegmentType::INTERP,
                    flags: types::SegmentFlags::READABLE,
                    offset: section.header.offset,
                    filesz: section.header.size,
                    vaddr: section.header.addr,
                    paddr: section.header.addr,
                    memsz: section.header.size,
                    align: 0x1,
                });
            }
            _ => {}
        }

        if section.header.flags.contains(types::SectionFlags::TLS) {
            r.push(segment::SegmentHeader {
                phtype: types::SegmentType::TLS,
                flags: types::SegmentFlags::READABLE,
                offset: section.header.offset,
                filesz: section.header.size,
                vaddr: section.header.addr,
                paddr: section.header.addr,
                memsz: section.header.size,
                align: 0x10,
            });
        }

        //emulate ld behaviour by just skipping over sections that are not allocateable,
        //sometimes actually allocating them. pretty weird, but i'm scared of more kernel gotchas
        //if i diverge from ld behaviour
        if !section.header.flags.contains(types::SectionFlags::ALLOC) {
            continue;
        }

        if section.header.shtype == types::SectionType::NOBITS {
            voff = section.header.addr + section.header.size;
            poff = section.header.offset;
            continue;
        }

        if section.header.offset as i64 + vshift != section.header.addr as i64 {
            r.push(segment::SegmentHeader {
                phtype: types::SegmentType::LOAD,
                flags: flags,
                offset: pstart,
                filesz: poff - pstart,
                vaddr: vstart,
                paddr: vstart,
                memsz: voff - vstart,
                align: 0x200000,
            });

            vshift = section.header.addr as i64 - section.header.offset as i64;
            vstart = section.header.addr;
            pstart = section.header.offset;
            flags = types::SegmentFlags::READABLE;
        }

        voff = section.header.addr + section.header.size;
        poff = section.header.offset + match section.header.shtype {
            types::SectionType::NOBITS => 0,
            _ => section.header.size,
        };

        if section
            .header
            .flags
            .contains(types::SectionFlags::EXECINSTR)
        {
            flags.insert(types::SegmentFlags::EXECUTABLE);
        }
        if section.header.flags.contains(types::SectionFlags::WRITE) {
            flags.insert(types::SegmentFlags::WRITABLE);
        }
    }
    r.push(segment::SegmentHeader {
        phtype: types::SegmentType::LOAD,
        flags: flags,
        offset: pstart,
        filesz: poff - pstart,
        vaddr: vstart,
        paddr: vstart,
        memsz: voff - vstart,
        align: 0x200000,
    });

    if elf.sections[1].header.offset > elf.sections[1].header.addr {
        return Err(Error::FirstSectionOffsetCanNotBeLargerThanAddress);
    }

    let first_vshift = elf.sections[1].header.addr - elf.sections[1].header.offset;
    let segments_size = segment::SegmentHeader::entsize(&elf.header) * (r.len() + 1);
    r.insert(
        0,
        segment::SegmentHeader {
            phtype: types::SegmentType::PHDR,
            flags: types::SegmentFlags::READABLE | types::SegmentFlags::EXECUTABLE,
            offset: elf.header.size() as u64,
            filesz: segments_size as u64,
            vaddr: first_vshift + elf.header.size() as u64,
            paddr: first_vshift + elf.header.size() as u64,
            memsz: segments_size as u64,
            align: 0x8,
        },
    );

    Ok(r)
}


