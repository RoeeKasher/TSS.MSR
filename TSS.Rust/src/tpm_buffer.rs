// //! TPM Buffer implementation for serialization and deserialization

// use crate::error::TpmError;
// use std::convert::TryFrom;

// /// Buffer for TPM data serialization/deserialization
// pub struct TpmBuffer {
//     /// The underlying byte buffer
//     data: Vec<u8>,
//     /// Current read position when deserializing
//     position: usize,
// }

// impl TpmBuffer {
//     /// Creates a new empty TPM buffer
//     pub fn new() -> Self {
//         Self {
//             data: Vec::new(),
//             position: 0,
//         }
//     }

//     /// Get current buffer as vector
//     pub fn to_vec(&self) -> Vec<u8> {
//         self.data.clone()
//     }

//     /// Write a u8 value to the buffer
//     pub fn write_u8(&mut self, value: u8) -> Result<(), TpmError> {
//         self.data.push(value);
//         Ok(())
//     }

//     /// Write a u16 value to the buffer in big-endian format
//     pub fn write_u16(&mut self, value: u16) -> Result<(), TpmError> {
//         self.data.extend_from_slice(&value.to_be_bytes());
//         Ok(())
//     }

//     /// Write a u32 value to the buffer in big-endian format
//     pub fn write_u32(&mut self, value: u32) -> Result<(), TpmError> {
//         self.data.extend_from_slice(&value.to_be_bytes());
//         Ok(())
//     }

//     /// Write a u64 value to the buffer in big-endian format
//     pub fn write_u64(&mut self, value: u64) -> Result<(), TpmError> {
//         self.data.extend_from_slice(&value.to_be_bytes());
//         Ok(())
//     }

//     /// Read a u8 value from the buffer
//     pub fn read_u8(&mut self) -> Result<u8, TpmError> {
//         if self.position >= self.data.len() {
//             return Err(TpmError::BufferUnderflow);
//         }
        
//         let value = self.data[self.position];
//         self.position += 1;
//         Ok(value)
//     }

//     /// Read a u16 value from the buffer in big-endian format
//     pub fn read_u16(&mut self) -> Result<u16, TpmError> {
//         if self.position + 2 > self.data.len() {
//             return Err(TpmError::BufferUnderflow);
//         }
        
//         let bytes = [self.data[self.position], self.data[self.position + 1]];
//         self.position += 2;
//         Ok(u16::from_be_bytes(bytes))
//     }

//     /// Read a u32 value from the buffer in big-endian format
//     pub fn read_u32(&mut self) -> Result<u32, TpmError> {
//         if self.position + 4 > self.data.len() {
//             return Err(TpmError::BufferUnderflow);
//         }
        
//         let bytes = [
//             self.data[self.position],
//             self.data[self.position + 1],
//             self.data[self.position + 2],
//             self.data[self.position + 3],
//         ];
//         self.position += 4;
//         Ok(u32::from_be_bytes(bytes))
//     }

//     /// Read a u64 value from the buffer in big-endian format
//     pub fn read_u64(&mut self) -> Result<u64, TpmError> {
//         if self.position + 8 > self.data.len() {
//             return Err(TpmError::BufferUnderflow);
//         }
        
//         let bytes = [
//             self.data[self.position],
//             self.data[self.position + 1],
//             self.data[self.position + 2],
//             self.data[self.position + 3],
//             self.data[self.position + 4],
//             self.data[self.position + 5],
//             self.data[self.position + 6],
//             self.data[self.position + 7],
//         ];
//         self.position += 8;
//         Ok(u64::from_be_bytes(bytes))
//     }

//     /// Write a union to the buffer
//     pub fn write_union(&mut self, value: &dyn TpmUnion) -> Result<(), TpmError> {
//         // First write the selector value
//         self.write_u32(value.get_union_selector())?;
        
//         // Then serialize the union content
//         if let Some(serializable) = value.as_any().downcast_ref::<dyn TpmStructure>() {
//             serializable.serialize(self)?;
//         }
        
//         Ok(())
//     }

//     /// Read a union from the buffer
//     pub fn read_union(&mut self, value: &mut dyn TpmUnion) -> Result<(), TpmError> {
//         // Union selector was already read before this is called
        
//         // Deserialize the union content
//         if let Some(deserializable) = value.as_any_mut().downcast_mut::<dyn TpmStructure>() {
//             deserializable.deserialize(self)?;
//         }
        
//         Ok(())
//     }

//     /// Write a sized buffer (preceded by u16 size)
//     pub fn write_sized_buffer(&mut self, buffer: &[u8]) -> Result<(), TpmError> {
//         if buffer.len() > u16::MAX as usize {
//             return Err(TpmError::BufferOverflow);
//         }
        
//         // Write size
//         self.write_u16(buffer.len() as u16)?;
        
//         // Write data
//         self.data.extend_from_slice(buffer);
        
//         Ok(())
//     }

//     /// Read a sized buffer (preceded by u16 size)
//     pub fn read_sized_buffer(&mut self) -> Result<Vec<u8>, TpmError> {
//         // Read size
//         let size = self.read_u16()? as usize;
        
//         if self.position + size > self.data.len() {
//             return Err(TpmError::BufferUnderflow);
//         }
        
//         // Read data
//         let buffer = self.data[self.position..self.position + size].to_vec();
//         self.position += size;
        
//         Ok(buffer)
//     }

//     /// Write a fixed-size array
//     pub fn write_fixed_array<T>(&mut self, array: &[T], size: usize) -> Result<(), TpmError> 
//     where
//         T: TpmStructure,
//     {
//         if array.len() != size {
//             return Err(TpmError::InvalidArraySize);
//         }
        
//         for item in array {
//             item.serialize(self)?;
//         }
        
//         Ok(())
//     }

//     /// Read a fixed-size array
//     pub fn read_fixed_array<T>(&mut self, size: usize) -> Result<Vec<T>, TpmError> 
//     where
//         T: TpmStructure + Default,
//     {
//         let mut array = Vec::with_capacity(size);
        
//         for _ in 0..size {
//             let mut item = T::default();
//             item.deserialize(self)?;
//             array.push(item);
//         }
        
//         Ok(array)
//     }

//     /// Write a variable-length array (preceded by u32 size)
//     pub fn write_sized_array<T>(&mut self, array: &[T]) -> Result<(), TpmError> 
//     where
//         T: TpmStructure,
//     {
//         // Write size
//         self.write_u32(array.len() as u32)?;
        
//         // Write elements
//         for item in array {
//             item.serialize(self)?;
//         }
        
//         Ok(())
//     }

//     /// Read a variable-length array (preceded by u32 size)
//     pub fn read_sized_array<T>(&mut self) -> Result<Vec<T>, TpmError> 
//     where
//         T: TpmStructure + Default,
//     {
//         // Read size
//         let size = self.read_u32()? as usize;
        
//         let mut array = Vec::with_capacity(size);
        
//         for _ in 0..size {
//             let mut item = T::default();
//             item.deserialize(self)?;
//             array.push(item);
//         }
        
//         Ok(array)
//     }
// }

// impl From<Vec<u8>> for TpmBuffer {
//     fn from(data: Vec<u8>) -> Self {
//         Self {
//             data,
//             position: 0,
//         }
//     }
// }

// /// The TpmStructure trait defines methods for serializing and deserializing TPM objects
// pub trait TpmStructure: Sized {
//     /// Serialize the structure to a TPM buffer
//     fn serialize(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError>;
    
//     /// Deserialize the structure from a TPM buffer
//     fn deserialize(&mut self, buffer: &mut TpmBuffer) -> Result<(), TpmError>;
// }

// // Extensions required for the TpmUnion trait - allows for downcasting
// pub trait AsAny {
//     fn as_any(&self) -> &dyn std::any::Any;
//     fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
// }

// // Implement AsAny for TpmUnion trait
// impl<T: TpmUnion + 'static> AsAny for T {
//     fn as_any(&self) -> &dyn std::any::Any {
//         self
//     }
    
//     fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
//         self
//     }
// }

// // Base trait for all TPM union types
// pub trait TpmUnion: AsAny {
//     /// Get the union selector value
//     fn get_union_selector(&self) -> u32;
// }