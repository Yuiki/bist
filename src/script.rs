pub enum Opcode {
    Dup,
    Hash160,
    EqualVerify,
    Checksig,
}

impl Opcode {
    pub fn value(&self) -> u8 {
        match self {
            Opcode::Dup => 0x76,
            Opcode::Hash160 => 0xA9,
            Opcode::EqualVerify => 0x88,
            Opcode::Checksig => 0xAC,
        }
    }
}
