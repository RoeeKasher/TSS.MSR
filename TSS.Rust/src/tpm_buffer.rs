use std::io::{self, Read, Write};

pub struct TpmBuffer {
    buffer: Vec<u8>,
    position: usize,
}

impl TpmBuffer {
    pub fn new() -> Self {
        TpmBuffer {
            buffer: Vec::new(),
            position: 0,
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        TpmBuffer {
            buffer: bytes,
            position: 0,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.buffer.clone()
    }

    pub fn write_u8(&mut self, value: u8) {
        self.buffer.push(value);
    }

    pub fn write_u16(&mut self, value: u16) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_u32(&mut self, value: u32) {
        self.buffer.extend_from_slice(&value.to_be_bytes());
    }

    pub fn read_u8(&mut self) -> io::Result<u8> {
        if self.position >= self.buffer.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Buffer underflow"));
        }
        let value = self.buffer[self.position];
        self.position += 1;
        Ok(value)
    }

    pub fn read_u16(&mut self) -> io::Result<u16> {
        if self.position + 2 > self.buffer.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Buffer underflow"));
        }
        let value = u16::from_be_bytes([self.buffer[self.position], self.buffer[self.position + 1]]);
        self.position += 2;
        Ok(value)
    }

    pub fn read_u32(&mut self) -> io::Result<u32> {
        if self.position + 4 > self.buffer.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Buffer underflow"));
        }
        let value = u32::from_be_bytes([
            self.buffer[self.position],
            self.buffer[self.position + 1],
            self.buffer[self.position + 2],
            self.buffer[self.position + 3],
        ]);
        self.position += 4;
        Ok(value)
    }

    pub fn reset(&mut self) {
        self.position = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_read() {
        let mut buffer = TpmBuffer::new();
        buffer.write_u8(0x12);
        buffer.write_u16(0x3456);
        buffer.write_u32(0x789ABCDE);

        buffer.reset();

        assert_eq!(buffer.read_u8().unwrap(), 0x12);
        assert_eq!(buffer.read_u16().unwrap(), 0x3456);
        assert_eq!(buffer.read_u32().unwrap(), 0x789ABCDE);
    }

    #[test]
    fn test_buffer_underflow() {
        let mut buffer = TpmBuffer::new();
        assert!(buffer.read_u8().is_err());
    }
}