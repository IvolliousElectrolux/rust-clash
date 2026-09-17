pub struct TlsWriter {
    buf: Vec<u8>,
}

impl TlsWriter {
    pub fn new(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    pub fn write_zeros(&mut self, n: usize) {
        self.buf.resize(self.buf.len() + n, 0);
    }

    pub fn begin_vector8(&mut self) -> usize {
        self.write_u8(0);
        self.buf.len()
    }

    pub fn begin_vector16(&mut self) -> usize {
        self.write_u16(0);
        self.buf.len()
    }

    pub fn begin_vector24(&mut self) -> usize {
        self.write_u8(0);
        self.write_u16(0);
        self.buf.len()
    }

    pub fn end_vector(&mut self, marker: usize, prefix: usize) {
        let length = self.buf.len() - marker;
        let start = marker - prefix;
        match prefix {
            1 => self.buf[start] = length as u8,
            2 => {
                self.buf[start] = (length >> 8) as u8;
                self.buf[start + 1] = length as u8;
            }
            3 => {
                self.buf[start] = (length >> 16) as u8;
                self.buf[start + 1] = (length >> 8) as u8;
                self.buf[start + 2] = length as u8;
            }
            _ => panic!("prefix"),
        }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}
