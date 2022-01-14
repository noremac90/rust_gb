
use crate::ppu::Ppu;

#[repr(packed)]

pub struct IORegs {
    pub joyp: u8,
    pub sb: u8,
    pub sc: u8,
    pub unused: u8,
    pub div: u8,
    pub tima: u8,
    pub tma: u8,
    pub tac: u8,
    pub unused2: [u8; 7], // 08, 09, 0A, 0B, 0C, 0D, 0E,
    pub _if: u8,
    pub nr10: u8,
    pub nr11: u8,
    pub nr12: u8,
    pub nr13: u8,
    pub nr14: u8,
    pub nr20: u8,
    pub nr21: u8,
    pub nr22: u8,
    pub nr23: u8,
    pub nr24: u8,
    pub nr30: u8,
    pub nr31: u8,
    pub nr32: u8,
    pub nr33: u8,
    pub nr34: u8,
    pub nr40: u8,
    pub nr41: u8,
    pub nr42: u8,
    pub nr43: u8,
    pub nr44: u8,
    pub nr50: u8,
    pub nr51: u8,
    pub nr52: u8,
    pub unused3: [u8; 9],
    pub wave: [u8; 0x10],
    pub lcdc: u8,
    pub stat: u8,
    pub scy: u8,
    pub scx: u8,
    pub ly: u8,
    pub lyc: u8,
    pub dma: u8,
    pub bgp: u8,
    pub obp0: u8,
    pub obp1: u8,
    pub wy: u8,
    pub wx: u8,
    pub unused4: [u8; 4],
    pub boot: u8
}

#[derive(Copy, Clone)]
pub struct OamEntry {
    pub y_pos: u8,
    pub x_pos: u8,
    pub tile: u8,
    pub attr: u8
}

pub struct Bus {
    bios: [u8; 0x100],
    rom: [[u8; 0x4000]; 2],
    vram: [u8; 0x2000],
    wram: [[u8; 0x1000]; 2],
    pub ior: IORegs,
    pub oam: [OamEntry; 0x40],
    hram: [u8; 0x7F],
    pub ie: u8,
    pub ppu: Ppu
}

impl Bus {
    pub fn new() -> Self {
        Self {
            bios: [0u8; 0x100],
            rom: [[0u8; 0x4000]; 2],
            vram: [0u8; 0x2000],
            wram: [[0u8; 0x1000]; 2],
            ior: unsafe { std::mem::MaybeUninit::zeroed().assume_init() },
            oam: [unsafe { std::mem::MaybeUninit::zeroed().assume_init() }; 0x40],
            hram: [0u8; 0x7F],
            ie: 0,
            ppu: Ppu::new()
        }
    }

    pub fn read(&self, addr: u16) -> u8 {
        if addr <= 0xFF && self.ior.boot == 0 {
            return self.bios[(addr & 0xFF) as usize];
        } else if addr <= 0x3FFF {
            return self.rom[0][(addr & 0x3FFF) as usize];
        } else if addr >= 0x4000 && addr <= 0x7FFF {
            return self.rom[1][(addr & 0x3FFF) as usize];
        } else if addr >= 0x8000 && addr <= 0x9FFF {
            return self.vram[(addr & 0x1FFF) as usize];
        } else if addr >= 0xC000 && addr <= 0xCFFF {
            return self.wram[0][(addr & 0xFFF) as usize];
        } else if addr >= 0xD000 && addr <= 0xDFFF {
            return self.wram[1][(addr & 0xFFF) as usize];
        } else if addr >= 0xFE00 && addr <= 0xFE9F {
            unsafe {
                let bytes = std::slice::from_raw_parts((&self.oam as *const [OamEntry; 0x40]) as *const u8, std::mem::size_of::<[OamEntry; 0x40]>());
                return bytes[(addr & 0xFF) as usize];
            }
        } else if addr >= 0xFF00 && addr <= 0xFF50 {
            unsafe {
                let bytes = std::slice::from_raw_parts((&self.ior as *const IORegs) as *const u8, std::mem::size_of::<IORegs>());
                return bytes[(addr & 0x7F) as usize];
            }
        } else if addr >= 0xFF80 && addr <= 0xFFFE {
            return self.hram[(addr & 0x7F) as usize];
        } else if addr == 0xFFFF {
            return self.ie;
        } else {
            return 0xFF;
        }
    }

    pub fn write(&mut self, addr: u16, val: u8) {

        if addr == 0xFF01 {
            print!("{}", val as char);
        }

        if addr <= 0x3FFF {
            
        } else if addr >= 0x4000 && addr <= 0x7FFF {
           
        } else if addr >= 0x8000 && addr <= 0x9FFF {
            self.vram[(addr & 0x1FFF) as usize] = val;
        } else if addr >= 0xC000 && addr <= 0xCFFF {
            self.wram[0][(addr & 0xFFF) as usize] = val;
        } else if addr >= 0xD000 && addr <= 0xDFFF {
            self.wram[1][(addr & 0xFFF) as usize] = val;
        } else if addr >= 0xFE00 && addr <= 0xFE9F {
            unsafe {
                let bytes = std::slice::from_raw_parts_mut((&mut self.oam as *mut [OamEntry; 0x40]) as *mut u8, std::mem::size_of::<[OamEntry; 0x40]>());
                bytes[(addr & 0xFF) as usize] = val;
            }
        } else if addr >= 0xFF00 && addr <= 0xFF50 {
            unsafe {
                let bytes = std::slice::from_raw_parts_mut((&mut self.ior as *mut IORegs) as *mut u8, std::mem::size_of::<IORegs>());
                bytes[(addr & 0x7F) as usize] = val;
            }
        } else if addr >= 0xFF80 && addr <= 0xFFFE {
            self.hram[(addr & 0x7F) as usize] = val;
        } else if addr == 0xFFFF {
            self.ie = val;
        } else {
            return;
        }
    }

    pub fn load_bios(&mut self, file: &'static str) {
        let bytes = std::fs::read(file).expect("File not found");
        self.bios[0..256].copy_from_slice(&bytes[0..256]);
    }

    pub fn load_rom(&mut self, file: &'static str) {
        let bytes = std::fs::read(file).expect("Rom not found");

        self.rom[0].copy_from_slice(&bytes[0..0x4000]);
        self.rom[1].copy_from_slice(&bytes[0x4000..0x8000]);
    }
}