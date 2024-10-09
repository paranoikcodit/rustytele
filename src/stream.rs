use std::io::{Cursor, Read, Result, Seek};

pub enum Endian {
    Big,
    Little,
}

pub struct Stream {
    pub cursor: Cursor<Vec<u8>>,
}

impl Stream {
    // Создаем новый поток из вектора байтов
    pub fn new(data: Vec<u8>) -> Self {
        Stream {
            cursor: Cursor::new(data),
        }
    }

    pub fn at_end(&self) -> bool {
        (self.cursor.position() as usize) >= (self.cursor.get_ref().len() - 1)
    }

    // Метод для чтения 32-битного целого числа в формате little-endian
    pub fn read_i32(&mut self, endian: Endian) -> Result<i32> {
        let mut buffer = [0u8; 4];
        self.cursor.read_exact(&mut buffer)?;

        Ok(match endian {
            Endian::Big => i32::from_be_bytes(buffer),
            Endian::Little => i32::from_le_bytes(buffer),
        })
    }

    pub fn read_buffer(&mut self) -> Result<Vec<u8>> {
        let length = self.read_u32(Endian::Big)?;

        if length == 0xffffffff {
            return Ok(vec![]);
        }

        self.read_raw_data(length as usize)
    }

    pub fn read_i64(&mut self, endian: Endian) -> Result<i64> {
        let mut buffer = [0u8; 8];
        self.cursor.read_exact(&mut buffer)?;

        Ok(match endian {
            Endian::Big => i64::from_be_bytes(buffer),
            Endian::Little => i64::from_le_bytes(buffer),
        })
    }

    pub fn read_u64(&mut self, endian: Endian) -> Result<u64> {
        let mut buffer = [0u8; 8];
        self.cursor.read_exact(&mut buffer)?;

        Ok(match endian {
            Endian::Big => u64::from_be_bytes(buffer),
            Endian::Little => u64::from_le_bytes(buffer),
        })
    }

    pub fn read_u32(&mut self, endian: Endian) -> Result<u32> {
        let mut buffer = [0u8; 4];
        self.cursor.read_exact(&mut buffer)?;

        Ok(match endian {
            Endian::Big => u32::from_be_bytes(buffer),
            Endian::Little => u32::from_le_bytes(buffer),
        })
    }

    // Метод для чтения произвольных данных (raw data) в виде вектора байтов
    pub fn read_raw_data(&mut self, size: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        self.cursor.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    // Метод для чтения строки (например, ASCII строки)
    pub fn read_string(&mut self, size: usize) -> Result<String> {
        let data = self.read_raw_data(size)?;
        Ok(String::from_utf8_lossy(&data).to_string())
    }

    pub fn read_to_end(&mut self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        self.cursor.read_to_end(&mut buffer)?;

        Ok(buffer)
    }
}
