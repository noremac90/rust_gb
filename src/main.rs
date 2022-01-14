
use cpu::Cpu;
use bus::Bus;
mod cpu;
mod bus;
mod ppu;



fn main() {
    let mut bus = Bus::new();
    bus.load_bios("DMG_ROM.bin");
    bus.load_rom("02.gb");

    let mut cpu = Cpu::new(bus);
    let mut ppu = ppu::Ppu::new();

    loop {
        if cpu.bus.ior.boot != 0 {
            cpu.dump();
        }
        cpu.step();
        ppu.tick(&mut cpu.bus);
    }
}
