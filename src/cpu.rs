
use crate::bus::Bus;

struct Regs {
    a: u8,
    f: u8,
    b: u8,
    c: u8,
    d: u8,
    e: u8,
    h: u8,
    l: u8,
    pc: u16,
    sp: u16
}

impl Regs {
    pub fn new() -> Self {
        Self { a: 0, f: 0, b: 0, c: 0, d: 0, e: 0, h: 0, l: 0, pc: 0, sp: 0 }
    }

    pub fn af(&self) -> u16 {
        u16::from_be_bytes([self.a, self.f])
    }

    pub fn hl(&self) -> u16 {
        u16::from_be_bytes([self.h, self.l])
    }

    pub fn bc(&self) -> u16 {
        u16::from_be_bytes([self.b, self.c])
    }

    pub fn de(&self) -> u16 {
        u16::from_be_bytes([self.d, self.e])
    }

    pub fn set_af(&mut self, value: u16) {
        let bytes = u16::to_be_bytes(value);
        self.a = bytes[0];
        self.f = bytes[1] & 0xF0;
    }

    pub fn set_bc(&mut self, value: u16) {
        let bytes = u16::to_be_bytes(value);
        self.b = bytes[0];
        self.c = bytes[1];
    }

    pub fn set_de(&mut self, value: u16) {
        let bytes = u16::to_be_bytes(value);
        self.d = bytes[0];
        self.e = bytes[1];
    }

    pub fn set_hl(&mut self, value: u16) {
        let bytes = u16::to_be_bytes(value);
        self.h = bytes[0];
        self.l = bytes[1];
    }

    pub fn setf_c(&mut self, val: bool) {
        if val {
            self.f |= 0x10;
        } else {
            self.f &= !0x10;
        }
    }

    pub fn setf_h(&mut self, val: bool) {
        if val {
            self.f |= 0x20;
        } else {
            self.f &= !0x20;
        }
    }

    pub fn setf_z(&mut self, val: bool) {
        if val {
            self.f |= 0x80;
        } else {
            self.f &= !0x80;
        }
    }

    pub fn setf_n(&mut self, val: bool) {
        if val {
            self.f |= 0x40;
        } else {
            self.f &= !0x40;
        }
    }

    pub fn getf_c(&self) -> bool {
        return self.f & 0x10 == 0x10;
    }

    pub fn getf_h(&self) -> bool {
        return self.f & 0x20 == 0x20;
    }

    pub fn getf_n(&self) -> bool {
        return self.f & 0x40 == 0x40;
    }

    pub fn getf_z(&self) -> bool {
        return self.f & 0x80 == 0x80;
    }
}

pub struct Cpu {
    regs: Regs,
    pub bus: Bus,
    pub cycles: u64,
    ime: bool,
}
#[derive(Eq, PartialEq)]
enum Condition {
    NZ,
    Z,
    C,
    NC,
    None
}

impl Cpu {
    pub fn new(bus: Bus) -> Self {
        Self {
            regs: Regs::new(),
            bus: bus,
            cycles: 0,
            ime: false,
        }
    }

    
    fn clock(&mut self) {
        self.cycles += 4;
    }

    fn push8(&mut self, val: u8) {
        self.regs.sp = self.regs.sp.wrapping_sub(1);
        self.write8(self.regs.sp, val);
    }

    fn pop8(&mut self) -> u8 {
        let val = self.read8(self.regs.sp);
        self.regs.sp = self.regs.sp.wrapping_add(1);
        return val;
    }

    fn push16(&mut self, val: u16) {
        let bytes = u16::to_be_bytes(val);
        self.push8(bytes[0]);
        self.push8(bytes[1]);
    }

    fn pop16(&mut self) -> u16 {
        u16::from_le_bytes([self.pop8(), self.pop8()])
    }

    fn read8(&mut self, addr: u16) -> u8 {
        self.clock();
        return self.bus.read(addr);
    }

    fn write8(&mut self, addr: u16, val: u8) {
        self.clock();
        self.bus.write(addr, val);
    }

    fn write16(&mut self, addr: u16, val: u16) {
        let bytes = u16::to_le_bytes(val);
        self.write8(addr, bytes[0]);
        self.write8(addr.wrapping_add(1), bytes[1]);
    }

    fn fetch16(&mut self) -> u16 {
        u16::from_le_bytes([self.fetch8(), self.fetch8()])
    }

    fn fetch8(&mut self) -> u8 {
        let result = self.read8(self.regs.pc);
        self.regs.pc += 1;
        return result;
    }

    fn check_int(&mut self) {
        if self.ime && (self.bus.ior._if & self.bus.ie) != 0 {
            let mask = self.bus.ior._if & self.bus.ie;
            println!("{:08b} {:08b}", self.bus.ior._if, self.bus.ie);
            println!("mask {:08b}", mask);
            let int = 0x40 + 0x8 * (mask & (!mask + 1)).trailing_zeros() as u16;
            println!("int {:02X}", int);

            self.bus.ior._if &= !mask;

            self.ime = false;
            self.op_rst(int);
        }
    }

    pub fn step(&mut self) {

        self.check_int();

        let ins = self.fetch8();

        match ins {
            0x00 => {}
            0x01 => { let imm = self.fetch16(); self.regs.set_bc(imm) }
            0x02 => self.write8(self.regs.bc(), self.regs.a),
            0x03 => { self.regs.set_bc(self.regs.bc().wrapping_add(1)); self.clock() }
            0x04 => self.regs.b = self.alu_inc8(self.regs.b),
            0x05 => self.regs.b = self.alu_dec8(self.regs.b),
            0x06 => self.regs.b = self.fetch8(),
            0x07 => self.regs.a = self.bit_rlc(self.regs.a, true),
            0x08 => { let addr = self.fetch16(); self.write16(addr, self.regs.sp) }
            0x09 => { let result = self.alu_add16(self.regs.hl(), self.regs.bc()); self.regs.set_hl(result) }
            0x0A => self.regs.a = self.read8(self.regs.bc()),
            0x0B => self.regs.set_bc(self.regs.bc().wrapping_sub(1)),
            0x0C => self.regs.c = self.alu_inc8(self.regs.c),
            0x0D => self.regs.c = self.alu_dec8(self.regs.c),
            0x0E => self.regs.c = self.fetch8(),
            0x0F => self.regs.a = self.bit_rrc(self.regs.a, true),

            0x10 => unimplemented!(),
            0x11 => { let imm = self.fetch16(); self.regs.set_de(imm) }
            0x12 => self.write8(self.regs.de(), self.regs.a),
            0x13 => { self.regs.set_de(self.regs.de().wrapping_add(1)); self.clock() }
            0x14 => self.regs.d = self.alu_inc8(self.regs.d),
            0x15 => self.regs.d = self.alu_dec8(self.regs.d),
            0x16 => self.regs.d = self.fetch8(),
            0x17 => self.regs.a = self.bit_rl(self.regs.a, true),
            0x18 => self.op_jr(Condition::None),
            0x19 => { let result = self.alu_add16(self.regs.hl(), self.regs.de()); self.regs.set_hl(result) }
            0x1A => self.regs.a = self.read8(self.regs.de()),
            0x1B => self.regs.set_de(self.regs.de().wrapping_sub(1)),
            0x1C => self.regs.e = self.alu_inc8(self.regs.e),
            0x1D => self.regs.e = self.alu_dec8(self.regs.e),
            0x1E => self.regs.e = self.fetch8(),
            0x1F => self.regs.a = self.bit_rr(self.regs.a, true),

            0x20 => self.op_jr(Condition::NZ),
            0x21 => { let imm = self.fetch16(); self.regs.set_hl(imm) },
            0x22 => { self.write8(self.regs.hl(), self.regs.a); self.regs.set_hl(self.regs.hl().wrapping_add(1)) }
            0x23 => { self.regs.set_hl(self.regs.hl().wrapping_add(1)); self.clock() }
            0x24 => self.regs.h = self.alu_inc8(self.regs.h),
            0x25 => self.regs.h = self.alu_dec8(self.regs.h),
            0x26 => self.regs.h = self.fetch8(),
            0x27 => { }
            0x28 => self.op_jr(Condition::Z),
            0x29 => { let result = self.alu_add16(self.regs.hl(), self.regs.hl()); self.regs.set_hl(result) }
            0x2A => { self.regs.a = self.read8(self.regs.hl()); self.regs.set_hl(self.regs.hl().wrapping_add(1)) }
            0x2B => self.regs.set_hl(self.regs.hl().wrapping_sub(1)),
            0x2C => self.regs.l = self.alu_inc8(self.regs.l),
            0x2D => self.regs.l = self.alu_dec8(self.regs.l),
            0x2E => self.regs.l = self.fetch8(),
            0x2F => { self.regs.a = !self.regs.a; self.regs.setf_n(true); self.regs.setf_h(true) }

            0x30 => self.op_jr(Condition::NC),
            0x31 => self.regs.sp = self.fetch16(),
            0x32 => { self.write8(self.regs.hl(), self.regs.a); self.regs.set_hl(self.regs.hl().wrapping_sub(1)) }
            0x33 => { self.regs.sp = self.regs.sp.wrapping_add(1); self.clock() }
            0x34 => { let mut val = self.read8(self.regs.hl()); val = self.alu_inc8(val); self.write8(self.regs.hl(), val) }
            0x35 => { let mut val = self.read8(self.regs.hl()); val = self.alu_dec8(val); self.write8(self.regs.hl(), val) }
            0x36 => { let imm = self.fetch8(); self.write8(self.regs.hl(), imm) }
            0x37 => { self.regs.setf_n(false); self.regs.setf_h(false); self.regs.setf_c(true) }
            0x38 => self.op_jr(Condition::C),
            0x39 => { let result = self.alu_add16(self.regs.hl(), self.regs.sp); self.regs.set_hl(result) }
            0x3A => { self.regs.a = self.read8(self.regs.hl()); self.regs.set_hl(self.regs.hl().wrapping_sub(1)) }
            0x3B => { self.regs.sp = self.regs.sp.wrapping_sub(1); self.clock() }
            0x3C => self.regs.a = self.alu_inc8(self.regs.a),
            0x3D => self.regs.a = self.alu_dec8(self.regs.a),
            0x3E => self.regs.a = self.fetch8(),
            0x3F => { self.regs.setf_n(false); self.regs.setf_h(false); self.regs.setf_c(!self.regs.getf_c()) }
            
            0x40 => self.regs.b = self.regs.b,
            0x41 => self.regs.b = self.regs.c,
            0x42 => self.regs.b = self.regs.d,
            0x43 => self.regs.b = self.regs.e,
            0x44 => self.regs.b = self.regs.h,
            0x45 => self.regs.b = self.regs.l,
            0x46 => self.regs.b = self.read8(self.regs.hl()),
            0x47 => self.regs.b = self.regs.a,
            0x48 => self.regs.c = self.regs.b,
            0x49 => self.regs.c = self.regs.c,
            0x4A => self.regs.c = self.regs.d,
            0x4B => self.regs.c = self.regs.e,
            0x4C => self.regs.c = self.regs.h,
            0x4D => self.regs.c = self.regs.l,
            0x4E => self.regs.c = self.read8(self.regs.hl()),
            0x4F => self.regs.c = self.regs.a,

            0x50 => self.regs.d = self.regs.b,
            0x51 => self.regs.d = self.regs.c,
            0x52 => self.regs.d = self.regs.d,
            0x53 => self.regs.d = self.regs.e,
            0x54 => self.regs.d = self.regs.h,
            0x55 => self.regs.d = self.regs.l,
            0x56 => self.regs.d = self.read8(self.regs.hl()),
            0x57 => self.regs.d = self.regs.a,
            0x58 => self.regs.e = self.regs.b,
            0x59 => self.regs.e = self.regs.c,
            0x5A => self.regs.e = self.regs.d,
            0x5B => self.regs.e = self.regs.e,
            0x5C => self.regs.e = self.regs.h,
            0x5D => self.regs.e = self.regs.l,
            0x5E => self.regs.e = self.read8(self.regs.hl()),
            0x5F => self.regs.e = self.regs.a,

            0x60 => self.regs.h = self.regs.b,
            0x61 => self.regs.h = self.regs.c,
            0x62 => self.regs.h = self.regs.d,
            0x63 => self.regs.h = self.regs.e,
            0x64 => self.regs.h = self.regs.h,
            0x65 => self.regs.h = self.regs.l,
            0x66 => self.regs.h = self.read8(self.regs.hl()),
            0x67 => self.regs.h = self.regs.a,

            0x68 => self.regs.l = self.regs.b,
            0x69 => self.regs.l = self.regs.c,
            0x6A => self.regs.l = self.regs.d,
            0x6B => self.regs.l = self.regs.e,
            0x6C => self.regs.l = self.regs.h,
            0x6D => self.regs.l = self.regs.l,
            0x6E => self.regs.l = self.read8(self.regs.hl()),
            0x6F => self.regs.l = self.regs.a,

            0x70 => self.write8(self.regs.hl(), self.regs.b),
            0x71 => self.write8(self.regs.hl(), self.regs.c),
            0x72 => self.write8(self.regs.hl(), self.regs.d),
            0x73 => self.write8(self.regs.hl(), self.regs.e),
            0x74 => self.write8(self.regs.hl(), self.regs.h),
            0x75 => self.write8(self.regs.hl(), self.regs.l),
            0x76 => unimplemented!(),
            0x77 => self.write8(self.regs.hl(), self.regs.a),
            0x78 => self.regs.a = self.regs.b,
            0x79 => self.regs.a = self.regs.c,
            0x7A => self.regs.a = self.regs.d,
            0x7B => self.regs.a = self.regs.e,
            0x7C => self.regs.a = self.regs.h,
            0x7D => self.regs.a = self.regs.l,
            0x7E => self.regs.a = self.read8(self.regs.hl()),
            0x7F => self.regs.a = self.regs.a,

            0x80 => self.regs.a = self.alu_add(self.regs.a, self.regs.b, false),
            0x81 => self.regs.a = self.alu_add(self.regs.a, self.regs.c, false),
            0x82 => self.regs.a = self.alu_add(self.regs.a, self.regs.d, false),
            0x83 => self.regs.a = self.alu_add(self.regs.a, self.regs.e, false),
            0x84 => self.regs.a = self.alu_add(self.regs.a, self.regs.h, false),
            0x85 => self.regs.a = self.alu_add(self.regs.a, self.regs.l, false),
            0x86 => { let rhs = self.read8(self.regs.hl()); self.regs.a = self.alu_add(self.regs.a, rhs, false) }
            0x87 => self.regs.a = self.alu_add(self.regs.a, self.regs.a, false),
            0x88 => self.regs.a = self.alu_add(self.regs.a, self.regs.b, true),
            0x89 => self.regs.a = self.alu_add(self.regs.a, self.regs.c, true),
            0x8A => self.regs.a = self.alu_add(self.regs.a, self.regs.d, true),
            0x8B => self.regs.a = self.alu_add(self.regs.a, self.regs.e, true),
            0x8C => self.regs.a = self.alu_add(self.regs.a, self.regs.h, true),
            0x8D => self.regs.a = self.alu_add(self.regs.a, self.regs.l, true),
            0x8E => { let rhs = self.read8(self.regs.hl()); self.regs.a = self.alu_add(self.regs.a, rhs, true) }
            0x8F => self.regs.a = self.alu_add(self.regs.a, self.regs.a, true),

            0x90 => self.regs.a = self.alu_sub(self.regs.a, self.regs.b, false),
            0x91 => self.regs.a = self.alu_sub(self.regs.a, self.regs.c, false),
            0x92 => self.regs.a = self.alu_sub(self.regs.a, self.regs.d, false),
            0x93 => self.regs.a = self.alu_sub(self.regs.a, self.regs.e, false),
            0x94 => self.regs.a = self.alu_sub(self.regs.a, self.regs.h, false),
            0x95 => self.regs.a = self.alu_sub(self.regs.a, self.regs.l, false),
            0x96 => { let rhs = self.read8(self.regs.hl()); self.regs.a = self.alu_sub(self.regs.a, rhs, false) }
            0x97 => self.regs.a = self.alu_sub(self.regs.a, self.regs.a, false),
            0x98 => self.regs.a = self.alu_sub(self.regs.a, self.regs.b, true),
            0x99 => self.regs.a = self.alu_sub(self.regs.a, self.regs.c, true),
            0x9A => self.regs.a = self.alu_sub(self.regs.a, self.regs.d, true),
            0x9B => self.regs.a = self.alu_sub(self.regs.a, self.regs.e, true),
            0x9C => self.regs.a = self.alu_sub(self.regs.a, self.regs.h, true),
            0x9D => self.regs.a = self.alu_sub(self.regs.a, self.regs.l, true),
            0x9E => { let rhs = self.read8(self.regs.hl()); self.regs.a = self.alu_sub(self.regs.a, rhs, true) }
            0x9F => self.regs.a = self.alu_sub(self.regs.a, self.regs.a, true),

            0xA0 => self.regs.a = self.alu_and(self.regs.a, self.regs.b),
            0xA1 => self.regs.a = self.alu_and(self.regs.a, self.regs.c),
            0xA2 => self.regs.a = self.alu_and(self.regs.a, self.regs.d),
            0xA3 => self.regs.a = self.alu_and(self.regs.a, self.regs.e),
            0xA4 => self.regs.a = self.alu_and(self.regs.a, self.regs.h),
            0xA5 => self.regs.a = self.alu_and(self.regs.a, self.regs.l),
            0xA6 => { let rhs = self.read8(self.regs.hl()); self.regs.a = self.alu_and(self.regs.a, rhs) }
            0xA7 => self.regs.a = self.alu_and(self.regs.a, self.regs.a),
            0xA8 => self.regs.a = self.alu_xor(self.regs.a, self.regs.b),
            0xA9 => self.regs.a = self.alu_xor(self.regs.a, self.regs.c),
            0xAA => self.regs.a = self.alu_xor(self.regs.a, self.regs.d),
            0xAB => self.regs.a = self.alu_xor(self.regs.a, self.regs.e),
            0xAC => self.regs.a = self.alu_xor(self.regs.a, self.regs.h),
            0xAD => self.regs.a = self.alu_xor(self.regs.a, self.regs.l),
            0xAE => { let rhs = self.read8(self.regs.hl()); self.regs.a = self.alu_xor(self.regs.a, rhs) }
            0xAF => self.regs.a = self.alu_xor(self.regs.a, self.regs.a),

            0xB0 => self.regs.a = self.alu_or(self.regs.a, self.regs.b),
            0xB1 => self.regs.a = self.alu_or(self.regs.a, self.regs.c),
            0xB2 => self.regs.a = self.alu_or(self.regs.a, self.regs.d),
            0xB3 => self.regs.a = self.alu_or(self.regs.a, self.regs.e),
            0xB4 => self.regs.a = self.alu_or(self.regs.a, self.regs.h),
            0xB5 => self.regs.a = self.alu_or(self.regs.a, self.regs.l),
            0xB6 => { let rhs = self.read8(self.regs.hl()); self.regs.a = self.alu_or(self.regs.a, rhs) }
            0xB7 => self.regs.a = self.alu_or(self.regs.a, self.regs.a),
            0xB8 => { self.alu_sub(self.regs.a, self.regs.b, false); },
            0xB9 => { self.alu_sub(self.regs.a, self.regs.c, false); },
            0xBA => { self.alu_sub(self.regs.a, self.regs.d, false); },
            0xBB => { self.alu_sub(self.regs.a, self.regs.e, false); },
            0xBC => { self.alu_sub(self.regs.a, self.regs.h, false); },
            0xBD => { self.alu_sub(self.regs.a, self.regs.l, false); },
            0xBE => { let rhs = self.read8(self.regs.hl()); self.alu_sub(self.regs.a, rhs, false); }
            0xBF => { self.alu_sub(self.regs.a, self.regs.a, false); },
            
            0xC0 => self.op_ret(Condition::NZ),
            0xC1 => { let val = self.pop16(); self.regs.set_bc(val) }
            0xC2 => self.op_jump(Condition::NZ),
            0xC3 => self.op_jump(Condition::None),
            0xC4 => self.op_call(Condition::NZ),
            0xC5 => { self.clock(); self.push16(self.regs.bc()) }
            0xC6 => { let rhs = self.fetch8(); self.regs.a = self.alu_add(self.regs.a, rhs, false) }
            0xC7 => self.op_rst(0x00),
            0xC8 => self.op_ret(Condition::Z),
            0xC9 => self.op_ret(Condition::None),
            0xCA => self.op_jump(Condition::Z),
            0xCB => self.op_cb(),
            0xCC => self.op_call(Condition::Z),
            0xCD => self.op_call(Condition::None),
            0xCE => { let rhs = self.fetch8(); self.regs.a = self.alu_add(self.regs.a, rhs, true) }
            0xCF => self.op_rst(0x08),
            
            0xD0 => self.op_ret(Condition::NC),
            0xD1 => { let val = self.pop16(); self.regs.set_de(val) }
            0xD2 => self.op_jump(Condition::NC),
            0xD4 => self.op_call(Condition::NC),
            0xD5 => { self.clock(); self.push16(self.regs.de()) }
            0xD6 => { let rhs = self.fetch8(); self.regs.a = self.alu_sub(self.regs.a, rhs, false) }
            0xD7 => self.op_rst(0x10),
            0xD8 => self.op_ret(Condition::C),
            0xD9 => { self.op_ret(Condition::None); self.ime = true }
            0xDA => self.op_jump(Condition::C),
            0xDC => self.op_call(Condition::C),
            0xDE => { let rhs = self.fetch8(); self.regs.a = self.alu_sub(self.regs.a, rhs, true) }
            0xDF => self.op_rst(0x18),
            
            0xE0 => { let addr = 0xFF00 + self.fetch8() as u16; self.write8(addr, self.regs.a) }
            0xE1 => { let val = self.pop16(); self.regs.set_hl(val) }
            0xE2 => self.write8(0xFF00 + self.regs.c as u16, self.regs.a),
            0xE5 => { self.clock(); self.push16(self.regs.hl()) }
            0xE6 => { let rhs = self.fetch8(); self.regs.a = self.alu_and(self.regs.a, rhs) }
            0xE7 => self.op_rst(0x20),
            0xE8 => { let imm = self.fetch8(); self.regs.sp = self.alu_add16i8(self.regs.sp, imm as i8); self.clock(); self.clock() }
            0xE9 => self.regs.pc = self.regs.hl(),
            0xEA => { let addr = self.fetch16(); self.write8(addr, self.regs.a) }
            0xEE => { let rhs = self.fetch8(); self.regs.a = self.alu_xor(self.regs.a, rhs) }
            0xEF => self.op_rst(0x28),
            
            0xF0 => { let addr = 0xFF00 + self.fetch8() as u16; self.regs.a = self.read8(addr) }
            0xF1 => { let val = self.pop16(); self.regs.set_af(val) }
            0xF2 => { let addr = 0xFF00 + self.regs.c as u16; self.regs.a = self.read8(addr) }
            0xF3 => self.ime = false,
            0xF5 => { self.clock(); self.push16(self.regs.af()) }
            0xF6 => { let rhs = self.fetch8(); self.regs.a = self.alu_or(self.regs.a, rhs) }
            0xF7 => self.op_rst(0x30),
            0xF8 => { let imm = self.fetch8(); let result = self.alu_add16i8(self.regs.sp, imm as i8); self.regs.set_hl(result); self.clock(); }
            0xF9 => { self.regs.sp = self.regs.hl(); self.clock() }
            0xFA => { let addr = self.fetch16(); self.regs.a = self.read8(addr) }
            0xFB => self.ime = true,
            0xFE => { let rhs = self.fetch8(); self.alu_sub(self.regs.a, rhs, false); }
            0xFF => self.op_rst(0x38),
            _ => panic!("Unknown opcode {:02X}", ins)
        }
    }


    fn op_rst(&mut self, addr: u16) {
        self.clock();
        self.push16(self.regs.pc);
        self.regs.pc = addr;
    }

    fn op_cb(&mut self) {
        let ins = self.fetch8();

        match ins {
            0x00 => self.regs.b = self.bit_rlc(self.regs.b, false),
            0x01 => self.regs.c = self.bit_rlc(self.regs.c, false),
            0x02 => self.regs.d = self.bit_rlc(self.regs.d, false),
            0x03 => self.regs.e = self.bit_rlc(self.regs.e, false),
            0x04 => self.regs.h = self.bit_rlc(self.regs.h, false),
            0x05 => self.regs.l = self.bit_rlc(self.regs.l, false),
            0x06 => { let mut val = self.read8(self.regs.hl()); val = self.bit_rlc(val, false); self.write8(self.regs.hl(), val) }
            0x07 => self.regs.a = self.bit_rlc(self.regs.a, false),
            0x08 => self.regs.b = self.bit_rrc(self.regs.b, false),
            0x09 => self.regs.c = self.bit_rrc(self.regs.c, false),
            0x0A => self.regs.d = self.bit_rrc(self.regs.d, false),
            0x0B => self.regs.e = self.bit_rrc(self.regs.e, false),
            0x0C => self.regs.h = self.bit_rrc(self.regs.h, false),
            0x0D => self.regs.l = self.bit_rrc(self.regs.l, false),
            0x0E => { let mut val = self.read8(self.regs.hl()); val = self.bit_rrc(val, false); self.write8(self.regs.hl(), val) }
            0x0F => self.regs.a = self.bit_rrc(self.regs.a, false),

            0x10 => self.regs.b = self.bit_rl(self.regs.b, false),
            0x11 => self.regs.c = self.bit_rl(self.regs.c, false),
            0x12 => self.regs.d = self.bit_rl(self.regs.d, false),
            0x13 => self.regs.e = self.bit_rl(self.regs.e, false),
            0x14 => self.regs.h = self.bit_rl(self.regs.h, false),
            0x15 => self.regs.l = self.bit_rl(self.regs.l, false),
            0x16 => { let mut val = self.read8(self.regs.hl()); val = self.bit_rl(val, false); self.write8(self.regs.hl(), val) }
            0x17 => self.regs.a = self.bit_rl(self.regs.a, false),
            0x18 => self.regs.b = self.bit_rr(self.regs.b, false),
            0x19 => self.regs.c = self.bit_rr(self.regs.c, false),
            0x1A => self.regs.d = self.bit_rr(self.regs.d, false),
            0x1B => self.regs.e = self.bit_rr(self.regs.e, false),
            0x1C => self.regs.h = self.bit_rr(self.regs.h, false),
            0x1D => self.regs.l = self.bit_rr(self.regs.l, false),
            0x1E => { let mut val = self.read8(self.regs.hl()); val = self.bit_rr(val, false); self.write8(self.regs.hl(), val) }
            0x1F => self.regs.a = self.bit_rr(self.regs.a, false),

            0x20 => self.regs.b = self.bit_sla(self.regs.b),
            0x21 => self.regs.c = self.bit_sla(self.regs.c),
            0x22 => self.regs.d = self.bit_sla(self.regs.d),
            0x23 => self.regs.e = self.bit_sla(self.regs.e),
            0x24 => self.regs.h = self.bit_sla(self.regs.h),
            0x25 => self.regs.l = self.bit_sla(self.regs.l),
            0x26 => { let mut val = self.read8(self.regs.hl()); val = self.bit_sla(val); self.write8(self.regs.hl(), val) }
            0x27 => self.regs.a = self.bit_sla(self.regs.a),
            0x28 => self.regs.b = self.bit_sra(self.regs.b),
            0x29 => self.regs.c = self.bit_sra(self.regs.c),
            0x2A => self.regs.d = self.bit_sra(self.regs.d),
            0x2B => self.regs.e = self.bit_sra(self.regs.e),
            0x2C => self.regs.h = self.bit_sra(self.regs.h),
            0x2D => self.regs.l = self.bit_sra(self.regs.l),
            0x2E => { let mut val = self.read8(self.regs.hl()); val = self.bit_sra(val); self.write8(self.regs.hl(), val) }
            0x2F => self.regs.a = self.bit_sra(self.regs.a),
            
            0x30 => self.regs.b = self.bit_swap(self.regs.b),
            0x31 => self.regs.c = self.bit_swap(self.regs.c),
            0x32 => self.regs.d = self.bit_swap(self.regs.d),
            0x33 => self.regs.e = self.bit_swap(self.regs.e),
            0x34 => self.regs.h = self.bit_swap(self.regs.h),
            0x35 => self.regs.l = self.bit_swap(self.regs.l),
            0x36 => { let mut val = self.read8(self.regs.hl()); val = self.bit_swap(val); self.write8(self.regs.hl(), val) }
            0x37 => self.regs.a = self.bit_swap(self.regs.a),
            0x38 => self.regs.b = self.bit_srl(self.regs.b),
            0x39 => self.regs.c = self.bit_srl(self.regs.c),
            0x3A => self.regs.d = self.bit_srl(self.regs.d),
            0x3B => self.regs.e = self.bit_srl(self.regs.e),
            0x3C => self.regs.h = self.bit_srl(self.regs.h),
            0x3D => self.regs.l = self.bit_srl(self.regs.l),
            0x3E => { let mut val = self.read8(self.regs.hl()); val = self.bit_srl(val); self.write8(self.regs.hl(), val) }
            0x3F => self.regs.a = self.bit_srl(self.regs.a),

            0x40 => self.bit_bit(self.regs.b, 0),
            0x41 => self.bit_bit(self.regs.c, 0),
            0x42 => self.bit_bit(self.regs.d, 0),
            0x43 => self.bit_bit(self.regs.e, 0),
            0x44 => self.bit_bit(self.regs.h, 0),
            0x45 => self.bit_bit(self.regs.l, 0),
            0x46 => { let val = self.read8(self.regs.hl()); self.bit_bit(val, 0) }
            0x47 => self.bit_bit(self.regs.a, 0),
            0x48 => self.bit_bit(self.regs.b, 1),
            0x49 => self.bit_bit(self.regs.c, 1),
            0x4A => self.bit_bit(self.regs.d, 1),
            0x4B => self.bit_bit(self.regs.e, 1),
            0x4C => self.bit_bit(self.regs.h, 1),
            0x4D => self.bit_bit(self.regs.l, 1),
            0x4E => { let val = self.read8(self.regs.hl()); self.bit_bit(val, 1) }
            0x4F => self.bit_bit(self.regs.a, 1),

            0x50 => self.bit_bit(self.regs.b, 2),
            0x51 => self.bit_bit(self.regs.c, 2),
            0x52 => self.bit_bit(self.regs.d, 2),
            0x53 => self.bit_bit(self.regs.e, 2),
            0x54 => self.bit_bit(self.regs.h, 2),
            0x55 => self.bit_bit(self.regs.l, 2),
            0x56 => { let val = self.read8(self.regs.hl()); self.bit_bit(val, 2) }
            0x57 => self.bit_bit(self.regs.a, 2),
            0x58 => self.bit_bit(self.regs.b, 3),
            0x59 => self.bit_bit(self.regs.c, 3),
            0x5A => self.bit_bit(self.regs.d, 3),
            0x5B => self.bit_bit(self.regs.e, 3),
            0x5C => self.bit_bit(self.regs.h, 3),
            0x5D => self.bit_bit(self.regs.l, 3),
            0x5E => { let val = self.read8(self.regs.hl()); self.bit_bit(val, 3) }
            0x5F => self.bit_bit(self.regs.a, 3),

            0x60 => self.bit_bit(self.regs.b, 4),
            0x61 => self.bit_bit(self.regs.c, 4),
            0x62 => self.bit_bit(self.regs.d, 4),
            0x63 => self.bit_bit(self.regs.e, 4),
            0x64 => self.bit_bit(self.regs.h, 4),
            0x65 => self.bit_bit(self.regs.l, 4),
            0x66 => { let val = self.read8(self.regs.hl()); self.bit_bit(val, 4) }
            0x67 => self.bit_bit(self.regs.a, 4),
            0x68 => self.bit_bit(self.regs.b, 5),
            0x69 => self.bit_bit(self.regs.c, 5),
            0x6A => self.bit_bit(self.regs.d, 5),
            0x6B => self.bit_bit(self.regs.e, 5),
            0x6C => self.bit_bit(self.regs.h, 5),
            0x6D => self.bit_bit(self.regs.l, 5),
            0x6E => { let val = self.read8(self.regs.hl()); self.bit_bit(val, 5) }
            0x6F => self.bit_bit(self.regs.a, 5),

            0x70 => self.bit_bit(self.regs.b, 6),
            0x71 => self.bit_bit(self.regs.c, 6),
            0x72 => self.bit_bit(self.regs.d, 6),
            0x73 => self.bit_bit(self.regs.e, 6),
            0x74 => self.bit_bit(self.regs.h, 6),
            0x75 => self.bit_bit(self.regs.l, 6),
            0x76 => { let val = self.read8(self.regs.hl()); self.bit_bit(val, 6) }
            0x77 => self.bit_bit(self.regs.a, 6),
            0x78 => self.bit_bit(self.regs.b, 7),
            0x79 => self.bit_bit(self.regs.c, 7),
            0x7A => self.bit_bit(self.regs.d, 7),
            0x7B => self.bit_bit(self.regs.e, 7),
            0x7C => self.bit_bit(self.regs.h, 7),
            0x7D => self.bit_bit(self.regs.l, 7),
            0x7E => { let val = self.read8(self.regs.hl()); self.bit_bit(val, 7) }
            0x7F => self.bit_bit(self.regs.a, 7),

            0x80 => self.regs.b = self.bit_res(self.regs.b, 0),
            0x81 => self.regs.c = self.bit_res(self.regs.c, 0),
            0x82 => self.regs.d = self.bit_res(self.regs.d, 0),
            0x83 => self.regs.e = self.bit_res(self.regs.e, 0),
            0x84 => self.regs.h = self.bit_res(self.regs.h, 0),
            0x85 => self.regs.l = self.bit_res(self.regs.l, 0),
            0x86 => { let mut val = self.read8(self.regs.hl()); val = self.bit_res(val, 0); self.write8(self.regs.hl(), val) }
            0x87 => self.regs.a = self.bit_res(self.regs.a, 0),
            0x88 => self.regs.b = self.bit_res(self.regs.b, 1),
            0x89 => self.regs.c = self.bit_res(self.regs.c, 1),
            0x8A => self.regs.d = self.bit_res(self.regs.d, 1),
            0x8B => self.regs.e = self.bit_res(self.regs.e, 1),
            0x8C => self.regs.h = self.bit_res(self.regs.h, 1),
            0x8D => self.regs.l = self.bit_res(self.regs.l, 1),
            0x8E => { let mut val = self.read8(self.regs.hl()); val = self.bit_res(val, 1); self.write8(self.regs.hl(), val) }
            0x8F => self.regs.a = self.bit_res(self.regs.a, 1),

            0x90 => self.regs.b = self.bit_res(self.regs.b, 2),
            0x91 => self.regs.c = self.bit_res(self.regs.c, 2),
            0x92 => self.regs.d = self.bit_res(self.regs.d, 2),
            0x93 => self.regs.e = self.bit_res(self.regs.e, 2),
            0x94 => self.regs.h = self.bit_res(self.regs.h, 2),
            0x95 => self.regs.l = self.bit_res(self.regs.l, 2),
            0x96 => { let mut val = self.read8(self.regs.hl()); val = self.bit_res(val, 2); self.write8(self.regs.hl(), val) }
            0x97 => self.regs.a = self.bit_res(self.regs.a, 2),
            0x98 => self.regs.b = self.bit_res(self.regs.b, 3),
            0x99 => self.regs.c = self.bit_res(self.regs.c, 3),
            0x9A => self.regs.d = self.bit_res(self.regs.d, 3),
            0x9B => self.regs.e = self.bit_res(self.regs.e, 3),
            0x9C => self.regs.h = self.bit_res(self.regs.h, 3),
            0x9D => self.regs.l = self.bit_res(self.regs.l, 3),
            0x9E => { let mut val = self.read8(self.regs.hl()); val = self.bit_res(val, 3); self.write8(self.regs.hl(), val) }
            0x9F => self.regs.a = self.bit_res(self.regs.a, 3),

            
            0xA0 => self.regs.b = self.bit_res(self.regs.b, 4),
            0xA1 => self.regs.c = self.bit_res(self.regs.c, 4),
            0xA2 => self.regs.d = self.bit_res(self.regs.d, 4),
            0xA3 => self.regs.e = self.bit_res(self.regs.e, 4),
            0xA4 => self.regs.h = self.bit_res(self.regs.h, 4),
            0xA5 => self.regs.l = self.bit_res(self.regs.l, 4),
            0xA6 => { let mut val = self.read8(self.regs.hl()); val = self.bit_res(val, 4); self.write8(self.regs.hl(), val) }
            0xA7 => self.regs.a = self.bit_res(self.regs.a, 4),
            0xA8 => self.regs.b = self.bit_res(self.regs.b, 5),
            0xA9 => self.regs.c = self.bit_res(self.regs.c, 5),
            0xAA => self.regs.d = self.bit_res(self.regs.d, 5),
            0xAB => self.regs.e = self.bit_res(self.regs.e, 5),
            0xAC => self.regs.h = self.bit_res(self.regs.h, 5),
            0xAD => self.regs.l = self.bit_res(self.regs.l, 5),
            0xAE => { let mut val = self.read8(self.regs.hl()); val = self.bit_res(val, 5); self.write8(self.regs.hl(), val) }
            0xAF => self.regs.a = self.bit_res(self.regs.a, 5),

            0xB0 => self.regs.b = self.bit_res(self.regs.b, 6),
            0xB1 => self.regs.c = self.bit_res(self.regs.c, 6),
            0xB2 => self.regs.d = self.bit_res(self.regs.d, 6),
            0xB3 => self.regs.e = self.bit_res(self.regs.e, 6),
            0xB4 => self.regs.h = self.bit_res(self.regs.h, 6),
            0xB5 => self.regs.l = self.bit_res(self.regs.l, 6),
            0xB6 => { let mut val = self.read8(self.regs.hl()); val = self.bit_res(val, 6); self.write8(self.regs.hl(), val) }
            0xB7 => self.regs.a = self.bit_res(self.regs.a, 6),
            0xB8 => self.regs.b = self.bit_res(self.regs.b, 7),
            0xB9 => self.regs.c = self.bit_res(self.regs.c, 7),
            0xBA => self.regs.d = self.bit_res(self.regs.d, 7),
            0xBB => self.regs.e = self.bit_res(self.regs.e, 7),
            0xBC => self.regs.h = self.bit_res(self.regs.h, 7),
            0xBD => self.regs.l = self.bit_res(self.regs.l, 7),
            0xBE => { let mut val = self.read8(self.regs.hl()); val = self.bit_res(val, 7); self.write8(self.regs.hl(), val) }
            0xBF => self.regs.a = self.bit_res(self.regs.a, 7),

            0xC0 => self.regs.b = self.bit_set(self.regs.b, 0),
            0xC1 => self.regs.c = self.bit_set(self.regs.c, 0),
            0xC2 => self.regs.d = self.bit_set(self.regs.d, 0),
            0xC3 => self.regs.e = self.bit_set(self.regs.e, 0),
            0xC4 => self.regs.h = self.bit_set(self.regs.h, 0),
            0xC5 => self.regs.l = self.bit_set(self.regs.l, 0),
            0xC6 => { let mut val = self.read8(self.regs.hl()); val = self.bit_set(val, 0); self.write8(self.regs.hl(), val) }
            0xC7 => self.regs.a = self.bit_set(self.regs.a, 0),
            0xC8 => self.regs.b = self.bit_set(self.regs.b, 1),
            0xC9 => self.regs.c = self.bit_set(self.regs.c, 1),
            0xCA => self.regs.d = self.bit_set(self.regs.d, 1),
            0xCB => self.regs.e = self.bit_set(self.regs.e, 1),
            0xCC => self.regs.h = self.bit_set(self.regs.h, 1),
            0xCD => self.regs.l = self.bit_set(self.regs.l, 1),
            0xCE => { let mut val = self.read8(self.regs.hl()); val = self.bit_set(val, 1); self.write8(self.regs.hl(), val) }
            0xCF => self.regs.a = self.bit_set(self.regs.a, 1),

            0xD0 => self.regs.b = self.bit_set(self.regs.b, 2),
            0xD1 => self.regs.c = self.bit_set(self.regs.c, 2),
            0xD2 => self.regs.d = self.bit_set(self.regs.d, 2),
            0xD3 => self.regs.e = self.bit_set(self.regs.e, 2),
            0xD4 => self.regs.h = self.bit_set(self.regs.h, 2),
            0xD5 => self.regs.l = self.bit_set(self.regs.l, 2),
            0xD6 => { let mut val = self.read8(self.regs.hl()); val = self.bit_set(val, 2); self.write8(self.regs.hl(), val) }
            0xD7 => self.regs.a = self.bit_set(self.regs.a, 2),
            0xD8 => self.regs.b = self.bit_set(self.regs.b, 3),
            0xD9 => self.regs.c = self.bit_set(self.regs.c, 3),
            0xDA => self.regs.d = self.bit_set(self.regs.d, 3),
            0xDB => self.regs.e = self.bit_set(self.regs.e, 3),
            0xDC => self.regs.h = self.bit_set(self.regs.h, 3),
            0xDD => self.regs.l = self.bit_set(self.regs.l, 3),
            0xDE => { let mut val = self.read8(self.regs.hl()); val = self.bit_set(val, 3); self.write8(self.regs.hl(), val) }
            0xDF => self.regs.a = self.bit_set(self.regs.a, 3),

            
            0xE0 => self.regs.b = self.bit_set(self.regs.b, 4),
            0xE1 => self.regs.c = self.bit_set(self.regs.c, 4),
            0xE2 => self.regs.d = self.bit_set(self.regs.d, 4),
            0xE3 => self.regs.e = self.bit_set(self.regs.e, 4),
            0xE4 => self.regs.h = self.bit_set(self.regs.h, 4),
            0xE5 => self.regs.l = self.bit_set(self.regs.l, 4),
            0xE6 => { let mut val = self.read8(self.regs.hl()); val = self.bit_set(val, 4); self.write8(self.regs.hl(), val) }
            0xE7 => self.regs.a = self.bit_set(self.regs.a, 4),
            0xE8 => self.regs.b = self.bit_set(self.regs.b, 5),
            0xE9 => self.regs.c = self.bit_set(self.regs.c, 5),
            0xEA => self.regs.d = self.bit_set(self.regs.d, 5),
            0xEB => self.regs.e = self.bit_set(self.regs.e, 5),
            0xEC => self.regs.h = self.bit_set(self.regs.h, 5),
            0xED => self.regs.l = self.bit_set(self.regs.l, 5),
            0xEE => { let mut val = self.read8(self.regs.hl()); val = self.bit_set(val, 5); self.write8(self.regs.hl(), val) }
            0xEF => self.regs.a = self.bit_set(self.regs.a, 5),

            0xF0 => self.regs.b = self.bit_set(self.regs.b, 6),
            0xF1 => self.regs.c = self.bit_set(self.regs.c, 6),
            0xF2 => self.regs.d = self.bit_set(self.regs.d, 6),
            0xF3 => self.regs.e = self.bit_set(self.regs.e, 6),
            0xF4 => self.regs.h = self.bit_set(self.regs.h, 6),
            0xF5 => self.regs.l = self.bit_set(self.regs.l, 6),
            0xF6 => { let mut val = self.read8(self.regs.hl()); val = self.bit_set(val, 6); self.write8(self.regs.hl(), val) }
            0xF7 => self.regs.a = self.bit_set(self.regs.a, 6),
            0xF8 => self.regs.b = self.bit_set(self.regs.b, 7),
            0xF9 => self.regs.c = self.bit_set(self.regs.c, 7),
            0xFA => self.regs.d = self.bit_set(self.regs.d, 7),
            0xFB => self.regs.e = self.bit_set(self.regs.e, 7),
            0xFC => self.regs.h = self.bit_set(self.regs.h, 7),
            0xFD => self.regs.l = self.bit_set(self.regs.l, 7),
            0xFE => { let mut val = self.read8(self.regs.hl()); val = self.bit_set(val, 7); self.write8(self.regs.hl(), val) }
            0xFF => self.regs.a = self.bit_set(self.regs.a, 7),

        }
    }


    fn alu_add16(&mut self, lhs: u16, rhs: u16) -> u16 {
        let (result, carry) = lhs.overflowing_add(rhs);

        self.regs.setf_n(false);
        self.regs.setf_h((lhs & 0xFFF) + (rhs & 0xFFF) & 0x1000 == 0x1000);
        self.regs.setf_c(carry);

        result
    }

    fn alu_add16i8(&mut self, lhs: u16, rhs: i8) -> u16 {
        let result = lhs.wrapping_add(rhs as u16);

        self.regs.setf_z(false);
        self.regs.setf_n(false);
        self.regs.setf_c(u16::wrapping_add(lhs & 0xFF, (rhs as u16) & 0xFF) & 0x100 == 0x100);
        self.regs.setf_h(u16::wrapping_add(lhs & 0xF, (rhs as u16) & 0xF) & 0x10 == 0x10);

        result
    }

    fn alu_inc8(&mut self, val: u8) -> u8 {
        let result = val.wrapping_add(1);

        self.regs.setf_z(result == 0);
        self.regs.setf_n(false);
        self.regs.setf_h((val & 0xF) + 1 & 0x10 == 0x10);

        return result;
    }

    fn alu_dec8(&mut self, val: u8) -> u8 {
        let result = val.wrapping_sub(1);

        self.regs.setf_z(result == 0);
        self.regs.setf_n(true);
        self.regs.setf_h((val & 0xF).wrapping_sub(1) & 0x10 == 0x10);

        return result;
    }

    fn alu_sub(&mut self, lhs: u8, rhs: u8, carry_op: bool) -> u8 {
        let (mut result, mut carry) = lhs.overflowing_sub(rhs);

        if carry_op {
            let (result_c, carry_c) = result.overflowing_sub(self.regs.getf_c() as u8);
            carry |= carry_c;
            result = result_c;
        }

        self.regs.setf_h(u8::wrapping_sub(lhs & 0xF, rhs & 0xF).wrapping_sub((carry_op & self.regs.getf_c()) as u8) & 0x10 == 0x10);
        self.regs.setf_c(carry);
        self.regs.setf_n(true);
        self.regs.setf_z(result == 0);
        result
    }

    fn alu_add(&mut self, lhs: u8, rhs: u8, carry_op: bool) -> u8 {
        let (mut result, mut carry) = lhs.overflowing_add(rhs);

        if carry_op {
            let (result_c, carry_c) = result.overflowing_add(self.regs.getf_c() as u8);
            carry |= carry_c;
            result = result_c;
        }

        
        self.regs.setf_n(false);
        self.regs.setf_z(result == 0);
        self.regs.setf_h((lhs & 0xF) + (rhs & 0xF) + (carry_op & self.regs.getf_c()) as u8 & 0x10 == 0x10);
        self.regs.setf_c(carry);

        result
    }

    pub fn dump(&self) {
        // A: 01 F: B0 B: 00 C: 13 D: 00 E: D8 H: 01 L: 4D SP: FFFE PC: 00:0101 (C3 13 02 CE)
        let next_bytes = [self.bus.read(self.regs.pc), self.bus.read(self.regs.pc + 1), self.bus.read(self.regs.pc + 2), self.bus.read(self.regs.pc + 3)];
        println!("A: {:02X} F: {:02X} B: {:02X} C: {:02X} D: {:02X} E: {:02X} H: {:02X} L: {:02X} SP: {:04X} PC: 00:{:04X} ({:02X} {:02X} {:02X} {:02X}) LY: {}",
            self.regs.a, self.regs.f, self.regs.b, self.regs.c, self.regs.d, self.regs.e, self.regs.h, self.regs.l, self.regs.sp, self.regs.pc,
            next_bytes[0], next_bytes[1], next_bytes[2], next_bytes[3], self.bus.ior.ly);
    }

    fn alu_xor(&mut self, lhs: u8, rhs: u8) -> u8 {
        let result = lhs ^ rhs;

        self.regs.setf_z(result == 0);
        self.regs.setf_h(false);
        self.regs.setf_c(false);
        self.regs.setf_n(false);

        return result;
    }

    fn alu_or(&mut self, lhs: u8, rhs: u8) -> u8 {
        let result = lhs | rhs;

        self.regs.setf_z(result == 0);
        self.regs.setf_h(false);
        self.regs.setf_c(false);
        self.regs.setf_n(false);

        return result;
    }

    fn alu_and(&mut self, lhs: u8, rhs: u8) -> u8 {
        let result = lhs & rhs;

        self.regs.setf_z(result == 0);
        self.regs.setf_h(true);
        self.regs.setf_c(false);
        self.regs.setf_n(false);

        return result;
    }

    fn bit_swap(&mut self, val: u8) -> u8 {
        let result = (val & 0x0F) << 4 | (val & 0xF0) >> 4;

        self.regs.setf_z(result == 0);
        self.regs.setf_n(false);
        self.regs.setf_c(false);
        self.regs.setf_h(false);

        result
    }

    fn bit_bit(&mut self, lhs: u8, bit: u8) {
        let result = lhs & (1u8 << bit);
        
        self.regs.setf_z(result == 0);
        self.regs.setf_n(false);
        self.regs.setf_h(true);

    }

    fn bit_set(&mut self, lhs: u8, bit: u8) -> u8 {
        lhs | (1u8 << bit)
    }

    fn bit_res(&mut self, lhs: u8, bit: u8) -> u8 {
        lhs & !(1u8 << bit)
    }

    fn bit_rl(&mut self, mut val: u8, accum: bool) -> u8 {
        let carry_out = val & 0x80 == 0x80;

        val <<= 1;
        val |= self.regs.getf_c() as u8;


        self.regs.setf_c(carry_out);
        if accum {
            self.regs.setf_z(false);
        } else {
            self.regs.setf_z(val == 0);
        }
        self.regs.setf_h(false);
        self.regs.setf_n(false);

        val
    }

    fn bit_sla(&mut self, mut val: u8) -> u8 {
        let carry_out = val & 0x80 == 0x80;

        val <<= 1;

        self.regs.setf_c(carry_out);
        self.regs.setf_z(val == 0);
        self.regs.setf_h(false);
        self.regs.setf_n(false);

        val
    }

    fn bit_sra(&mut self, mut val: u8) -> u8 {
        let top = val & 0x80;
        let carry_out = val & 0x01 == 0x01;

        val >>= 1;
        val |= top;

        self.regs.setf_c(carry_out);
        self.regs.setf_z(val == 0);
        self.regs.setf_h(false);
        self.regs.setf_n(false);

        val
    }

    fn bit_rlc(&mut self, mut val: u8, accum: bool) -> u8 {
        let carry_out = val & 0x80 == 0x80;

        val = val.rotate_left(1);

        self.regs.setf_c(carry_out);
        if accum {
            self.regs.setf_z(false);
        } else {
            self.regs.setf_z(val == 0);
        }
        self.regs.setf_h(false);
        self.regs.setf_n(false);

        val
    }

    fn bit_srl(&mut self, mut val: u8) -> u8 {
        let carry_out = val & 0x01 == 0x01;

        val >>= 1;

        self.regs.setf_c(carry_out);
        self.regs.setf_z(val == 0);
        self.regs.setf_h(false);
        self.regs.setf_n(false);

        val
    }

    fn bit_rr(&mut self, mut val: u8, accum: bool) -> u8 {
        let carry_out = val & 0x01 == 0x01;

        val >>= 1;

        val |= (self.regs.getf_c() as u8) << 7;

        self.regs.setf_c(carry_out);
        if accum {
            self.regs.setf_z(false);
        } else {
            self.regs.setf_z(val == 0);
        }
        self.regs.setf_h(false);
        self.regs.setf_n(false);

        val
    }

    fn bit_rrc(&mut self, mut val: u8, accum: bool) -> u8 {
        let carry_out = val & 0x01 == 0x01;

        val = val.rotate_right(1);

        self.regs.setf_c(carry_out);
        if accum {
            self.regs.setf_z(false);
        } else {
            self.regs.setf_z(val == 0);
        }
        self.regs.setf_h(false);
        self.regs.setf_n(false);

        val
    }

    fn op_call(&mut self, cond: Condition) {
        let addr = self.fetch16();

        if cond == Condition::NC && !self.regs.getf_c()
            || cond == Condition::C && self.regs.getf_c()
            || cond == Condition::NZ && !self.regs.getf_z()
            || cond == Condition::Z && self.regs.getf_z()
            || cond == Condition::None {
            self.clock();
            self.push16(self.regs.pc);
            self.regs.pc = addr;
        }
    }

    fn op_jump(&mut self, cond: Condition) {
        let addr = self.fetch16();

        if cond == Condition::NC && !self.regs.getf_c()
            || cond == Condition::C && self.regs.getf_c()
            || cond == Condition::NZ && !self.regs.getf_z()
            || cond == Condition::Z && self.regs.getf_z()
            || cond == Condition::None {
            self.clock();
            self.regs.pc = addr;
        }
    }

    fn op_ret(&mut self, cond: Condition) {
        self.clock();
        if cond == Condition::NC && !self.regs.getf_c()
            || cond == Condition::C && self.regs.getf_c()
            || cond == Condition::NZ && !self.regs.getf_z()
            || cond == Condition::Z && self.regs.getf_z()
            || cond == Condition::None {
            
            let addr = self.pop16();
            self.regs.pc = addr;
        }
    }

    fn op_jr(&mut self, cond: Condition) {
        let offset = self.fetch8() as i8;

        let addr = self.regs.pc.wrapping_add(offset as u16);

        if cond == Condition::NC && !self.regs.getf_c()
            || cond == Condition::C && self.regs.getf_c()
            || cond == Condition::NZ && !self.regs.getf_z()
            || cond == Condition::Z && self.regs.getf_z()
            || cond == Condition::None {
            self.regs.pc = addr;
        }
    }

}