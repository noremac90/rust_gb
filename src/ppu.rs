
use crate::Bus;
pub struct Ppu {
    line: u8,
    cycle: u16
}

impl Ppu {
    pub fn new() -> Self {
        Self {
            line: 0,
            cycle: 0,
        }
    }

    pub fn tick(&mut self, bus: &mut Bus) {
        self.cycle += 1;

        bus.ior.ly = self.line;

        if self.cycle > 456 {
            self.line += 1;
            self.cycle = 0;
        }

        if self.line > 153 {
            self.line = 0;
        }
    }
}