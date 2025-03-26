/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace CodeGen
{
    /// <summary> Rust TSS code generator </summary>
    internal class CGenRust : CodeGenBase
    {
        // Maps enum type to a map of enumerator names to values
        Dictionary<string, Dictionary<string, string>> EnumMap;

        public CGenRust(string rootDir) : base(rootDir, @"src\tpm_extensions.rs.snips") {}

        internal override void Generate()
        {
            EnumMap = new Dictionary<string, Dictionary<string, string>>();

            GenerateTpmTypesRs();
            UpdateExistingSource(@"src\tpm_types.rs");

            GenerateTpmCommandPrototypes();
            UpdateExistingSource(@"src\tpm2.rs");
        }

        /// <summary> Determines whether this struct is represented as a type alias in Rust </summary>
        static bool IsTypedefStruct(TpmStruct s)
        {
            return s.DerivedFrom != null && s.ContainingUnions.Count == 0;
        }

        static string CtorParamTypeFor(StructField f)
        {
            if (f.IsArray() || !f.IsValueType())
                return $"&{ToSnakeCase(f.TypeName)}";
            return ToSnakeCase(f.TypeName);
        }

        static string TransType(StructField f)
        {
            string typeName = f.TypeName;
            
            // Handle union object types
            if (f.MarshalType == MarshalType.UnionObject)
            {
                return $"Option<Box<dyn {ToSnakeCase(typeName)}>>";
            }
            
            // Handle types with generics (containers like Vec, Option, etc.)
            if (typeName.Contains("<") && typeName.Contains(">"))
            {
                int openBracketIndex = typeName.IndexOf('<');
                int closeBracketIndex = typeName.LastIndexOf('>');
                
                string baseType = typeName.Substring(0, openBracketIndex);
                string genericParams = typeName.Substring(openBracketIndex + 1, closeBracketIndex - openBracketIndex - 1);
                
                return $"{baseType}<{ToSnakeCase(genericParams)}>";
            }
            
            // Standard type conversion
            return ToSnakeCase(typeName);
        }

        string GetCommandReturnType(CommandFlavor gen, TpmStruct resp, string methodName,
                                    out string returnFieldName)
        {
            returnFieldName = null;
            if (gen == CommandFlavor.AsyncCommand)
                return "Result<(), TpmError>";

            string returnType = "Result<(), TpmError>";
            var respFields = resp.NonTagFields;
            if (ForceJustOneReturnParm.Contains(methodName))
            {
                respFields = respFields.Take(1).ToArray();
            }

            if (respFields.Count() > 1)
                return $"Result<{resp.Name}, TpmError>";

            if (respFields.Count() == 1)
            {
                returnFieldName = respFields[0].Name;
                returnType = $"Result<{TransType(respFields[0])}, TpmError>";
            }
            return returnType;
        }

        void GenerateTpmTypesRs()
        {
            Write("//! TPM type definitions");
            Write("");
            Write("use crate::error::TpmError;");
            Write("use crate::tpm_buffer::TpmBuffer;");
            Write("use crate::crypto::Crypto;");
            Write("use std::fmt;");
            Write("use num_enum::TryFromPrimitive;");
            Write("use std::collections::HashMap;");
            Write("use std::fmt::Debug;");
            Write("");
            
            // Generate traits
            WriteComment("Common trait for all TPM enumeration types");
            Write("pub trait TpmEnum {");
            TabIn("/// Get the numeric value of the enum");
            Write("fn get_value(&self) -> u32;");
            TabOut("}");
            Write("");

            WriteComment("Trait for structures that can be marshaled to/from TPM wire format");
            TabIn("pub trait TpmStructure {");
            Write("/// Serialize the structure to a TPM buffer");
            Write("fn serialize(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError>;");
            Write("");
            Write("/// Deserialize the structure from a TPM buffer");
            Write("fn deserialize(&mut self, buffer: &mut TpmBuffer) -> Result<(), TpmError>;");

            Write("fn toTpm(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError>;");
            Write("fn initFromTpm(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError>;");
            Write("fn fromTpm(&self, buf: &mut TpmBuffer) -> Result<(), TpmError>;");
            Write("fn fromBytes(&self, buf: &mut Vec<u8>) -> Result<(), TpmError>;");

            
            TabOut("}");
            
            WriteComment("Trait for TPM union types");
            Write("pub trait TpmUnion : TpmStructure { }");
            Write("");

            // Generate union factory
            GenUnionFactory();

            // Generate the enums, bitfields, unions, and structs
            foreach (var e in TpmTypes.Get<TpmEnum>())
                GenEnum(e);

            foreach (var bf in TpmTypes.Get<TpmBitfield>())
                GenBitfield(bf);

            foreach (var u in TpmTypes.Get<TpmUnion>())
                GenUnion(u);

            foreach (var s in TpmTypes.Get<TpmStruct>())
                GenStructDecl(s);

            // Generate the enum maps
            GenEnumMap();
        }

        /// <summary>
        /// Checks if an enum has duplicate values among its elements
        /// </summary>
        private bool HasDuplicateValues(List<TpmNamedConstant> elements)
        {
            HashSet<long> values = new HashSet<long>();
            foreach (var element in elements)
            {
                if (!values.Add(element.NumericValue))
                {
                    return true; // Found a duplicate
                }
            }
            return false;
        }

        void GenEnum(TpmType e, List<TpmNamedConstant> elements)
        {
            bool hasDuplicates = HasDuplicateValues(elements);
            
            WriteComment(e);
               
            var enumVals = new Dictionary<string, string>();
            
            if (hasDuplicates)
            {
                // Generate a newtype struct with constants for enums with duplicates
                WriteComment("Enum with duplicated values - using struct with constants");
                Write($"#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]");
                Write($"pub struct {e.Name}(pub u{e.GetFinalUnderlyingType().GetSize() * 8});");
                Write("");
                
                // Generate constants for each enum value
                TabIn($"impl {e.Name} {{");
                
                foreach (var elt in elements)
                {
                    WriteComment(AsSummary(elt.Comment));
                    var enumValue = ToRustEnumValue(elt);
                    var originalValueComment = "";
                    if (enumValue != elt.Value)
                    {
                        originalValueComment = $" // Original value: {elt.Value}";
                    }
                    
                    Write($"pub const {elt.Name}: Self = Self({enumValue});{originalValueComment}");
                    
                    // Do not include artificially added named constants into the name conversion maps
                    if (elt.SpecName != null)
                        enumVals[elt.Name] = e is TpmEnum ? ToHex(elt.NumericValue) : elt.Value;
                }
                
                // Add TryFrom implementation for the newtype struct
                Write("");
                TabIn($"pub fn try_from(value: i{e.GetFinalUnderlyingType().GetSize() * 8}) -> Result<Self, TpmError> {{");
                TabIn("match value {");
                foreach (var elt in elements.GroupBy(x => x.NumericValue).Select(g => g.First()))
                {
                    // Only include first occurrence of each value to avoid duplicate match arms
                    Write($"{(ulong)elt.NumericValue} => Ok(Self::{elt.Name}), // Original value: {elt.Value}");
                }
                Write("_ => Err(TpmError::InvalidEnumValue),");
                TabOut("}");
                TabOut("}");
                
                TabOut("}");
                Write("");
                
                // Implement TpmEnum trait for the struct
                TabIn($"impl TpmEnum for {e.Name} {{");
                TabIn("fn get_value(&self) -> u32 {");
                Write("self.0.into()");
                TabOut("}");
                TabOut("}");
                Write("");
                
                // Add numeric conversions
                TabIn($"impl From<{e.Name}> for u32 {{");
                TabIn($"fn from(value: {e.Name}) -> Self {{");
                Write("value.0.into()");
                TabOut("}", false);
                TabOut("}");
                Write("");
                
                TabIn($"impl From<{e.Name}> for i32 {{");
                TabIn($"fn from(value: {e.Name}) -> Self {{");
                Write("value.0 as i32");
                TabOut("}", false);
                TabOut("}");
                Write("");
                
                // Implement Display trait
                TabIn($"impl fmt::Display for {e.Name} {{");
                TabIn("fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {");
                TabIn("match self.0 {");
                
                // Group by value to avoid duplicate match arms
                var grouped = elements.GroupBy(x => x.NumericValue);
                foreach (var group in grouped)
                {
                    if (group.Count() == 1)
                    {
                        // Only one variant for this value
                        Write($"{(ulong)group.Key} => write!(f, \"{group.First().Name}\"),");
                    }
                    else
                    {
                        // Multiple variants for this value
                        var variants = group.Select(elt => elt.Name);
                        Write($"{(ulong)group.Key} => write!(f, \"One of <{string.Join(", ", variants)}>\"),");
                    }
                }
                
                Write("_ => write!(f, \"Unknown({:?})\", self.0),");
                TabOut("}");
                TabOut("}");
                TabOut("}");
            }
            else
            {
                // Original enum generation for types without duplicates
                Write($"#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TryFromPrimitive, Default)]");
                Write($"#[repr(i{e.GetFinalUnderlyingType().GetSize() * 8})]");
                Write($"pub enum {e.Name} {{");
                TabIn();

                Write("#[default]");
                foreach (var elt in elements)
                {
                    WriteComment(AsSummary(elt.Comment));
                    string delimiter = Separator(elt, elements).Replace(",", ",");

                    var enumValue = ToRustEnumValue(elt);
                    var originalValueComment = "";
                    if (enumValue != elt.Value)
                    {
                        originalValueComment = $" // Original value: {elt.Value}";
                    }

                    Write($"{ToRustEnumMemberName(elt.Name)} = {enumValue}{delimiter}{originalValueComment}");

                    // Do not include artificially added named constants into the name conversion maps
                    if (elt.SpecName != null)
                        enumVals[elt.Name] = e is TpmEnum ? ToHex(elt.NumericValue) : elt.Value;
                }
                TabOut("}");
                
                // Implement TpmEnum trait for the enum
                TabIn($"impl TpmEnum for {e.Name} {{");
                TabIn("fn get_value(&self) -> u32 {");
                Write("*self as u32");
                TabOut("}");
                TabOut("}");
                Write("");
                
                // Add numeric conversions
                TabIn($"impl From<{e.Name}> for u32 {{");
                TabIn($"fn from(value: {e.Name}) -> Self {{");
                Write("value as u32");
                TabOut("}");
                TabOut("}");
                Write("");
                
                TabIn($"impl From<{e.Name}> for i32 {{");
                TabIn($"fn from(value: {e.Name}) -> Self {{");
                Write("value as i32");
                TabOut("}");
                TabOut("}");
                Write("");
                
                // Implement Display trait
                TabIn($"impl fmt::Display for {e.Name} {{");
                TabIn("fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {");
                TabIn("match self {");
                foreach (var elt in elements)
                {
                    string memberName = ToRustEnumMemberName(elt.Name);
                    Write($"Self::{memberName} => write!(f, \"{memberName}\"),");
                }
                TabOut("}", false);
                TabOut("}", false);
                TabOut("}", false);
            }
            Write("");
            
            EnumMap[e.Name] = hasDuplicates ? new Dictionary<string, string>() : enumVals;
        }

        void GenEnum(TpmEnum e)
        {
            GenEnum(e, e.Members);
        }

        void GenBitfield(TpmBitfield bf)
        {
            var bitfieldElements = GetBifieldElements(bf);
            bool hasDuplicates = HasDuplicateValues(bitfieldElements);
            
            if (hasDuplicates)
            {
                // Generate the enum with constants approach
                GenEnum(bf, bitfieldElements);
                
                // Add bitwise operations for flags using the newtype pattern
                TabIn($"impl std::ops::BitOr for {bf.Name} {{");
                Write("type Output = Self;");
                Write("");
                TabIn("fn bitor(self, rhs: Self) -> Self::Output {");
                Write($"Self(self.0 | rhs.0)");
                TabOut("}");
                TabOut("}");
                Write("");
                
                // From impl
                TabIn($"impl From<u{bf.GetFinalUnderlyingType().GetSize() * 8}> for {bf.Name} {{");
                TabIn($"fn from(value: u{bf.GetFinalUnderlyingType().GetSize() * 8}) -> Self {{");
                Write($"Self(value.into())");
                TabOut("}", false);
                TabOut("}");
                Write("");
            }
            else
            {
                // Original implementation for bitfields without duplicates
                GenEnum(bf, bitfieldElements);

                // Add bitwise operations for flags
                Write($"impl std::ops::BitOr for {bf.Name} {{");
                TabIn("type Output = Self;");
                Write("");
                Write("fn bitor(self, rhs: Self) -> Self::Output {");
                TabIn($"unsafe {{ std::mem::transmute(self as u{bf.GetFinalUnderlyingType().GetSize() * 8} | rhs as u{bf.GetFinalUnderlyingType().GetSize() * 8}) }}");
                TabOut("}");
                TabOut("}");
                Write("");

                // From u32/u16/u8 implementation
                Write($"impl From<u{bf.GetFinalUnderlyingType().GetSize() * 8}> for {bf.Name} {{");
                TabIn($"fn from(value: u{bf.GetFinalUnderlyingType().GetSize() * 8}) -> Self {{");
                TabIn($"unsafe {{ std::mem::transmute(value) }}");
                TabOut("}");
                TabOut("}");
                Write("");
            }
        }

        void GenUnion(TpmUnion u)
        {
            if (!u.Implement)
                return;

            WriteComment(u);
            TabIn($"pub trait {u.Name} : TpmUnion {{");
            Write($"fn GetUnionSelector(&self) -> {GetUnionSelectorType(u)};");
            TabOut("}");

            TabIn($"impl Debug for dyn {u.Name} {{");
            TabIn("fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {");
            Write("write!(f, \"{}\", self.GetUnionSelector())");
            TabOut("}", false);
            TabOut("}");
        }
            
        void GenGetUnionSelector(TpmStruct s)
        {
            string selType = GetUnionMemberSelectorInfo(s, out string selVal);
            if (selType == null)
            {
                return;
            }

            Write($"impl TpmUnion for {s.Name} {{ }}");

            foreach (var containingUnion in s.ContainingUnions)
            {
                WriteComment($"{selType} trait implementation");

                TabIn($"impl {containingUnion.Name} for {s.Name} {{");

                TabIn($"fn GetUnionSelector(&self) -> {selType} {{");
                Write(selVal);
                TabOut("}", false);

                TabOut("}");
            }
        }

        void GenStructDecl(TpmStruct s)
        {
            bool hasBase = s.DerivedFrom != null; // Has a non-trivial base type?
            string structName = s.Name;

            if (IsTypedefStruct(s))
            {
                Debug.Assert(s.Fields.Count == 0);
                WriteComment(s);
                Write($"pub type {structName} = {s.DerivedFrom.Name};");
                Write("");
                return;
            }

            WriteComment(s);
            Write($"#[derive(Debug, Default)]");
            Write($"pub struct {structName} {{");
            TabIn();

            // Fields
            foreach (var f in s.NonSizeFields)
            {
                if (f.MarshalType == MarshalType.ConstantValue)
                    // No member field for a constant tag
                    continue;

                WriteComment(f);
                if (f.MarshalType == MarshalType.UnionSelector)
                {
                    // Selectors are handled through methods in Rust
                    continue;
                }

                Write($"pub {ToSnakeCase(f.Name)}: {TransType(f)},");
            }
            
            TabOut("}");
            Write("");
            
            // Implement struct methods
            Write($"impl {structName} {{");
            TabIn();
            
            // Constructor
            if (!s.Info.IsResponse() && s.NonTagFields.Count() > 0)
            {
                Write("/// Creates a new instance with the specified values");
                Write("pub fn new(");
                TabIn();
                
                foreach (var f in s.NonTagFields)
                {
                    if (f.MarshalType == MarshalType.ConstantValue || f.MarshalType == MarshalType.UnionSelector)
                        continue;
                        
                    Write($"{ToSnakeCase(f.Name)}: {TransType(f)},");
                }
                
                Write($") -> Self {{");
                TabIn("Self {");
                
                foreach (var f in s.NonTagFields)
                {
                    if (f.MarshalType == MarshalType.ConstantValue || f.MarshalType == MarshalType.UnionSelector)
                        continue;
                        
                    Write($"{ToSnakeCase(f.Name)},");
                }
                
                TabOut("}", false);
                TabOut("}", false);
                Write("");
            }
            
            // // Selector methods for unions
            // foreach (var f in s.Fields.Where(f => f.MarshalType == MarshalType.UnionSelector))
            // {
            //     var unionField = f.RelatedUnion;
            //     var u = (TpmUnion)unionField.Type;
                
            //     Write($"/// Get the {f.Name} selector value");
            //     Write($"pub fn {ToSnakeCase(f.Name)}(&self) -> {f.TypeName} {{");
            //     TabIn();
                
            //     TabIn($"match &self.{ToSnakeCase(unionField.Name)} {{");
            //     Write($"Some(u) => {f.TypeName}.try_from(u.GetUnionSelector())?,");
            //     if (u.NullSelector == null)
            //     {
            //         Write("None => 0 as _,");
            //     }
            //     else
            //     {
            //         Write($"None => {u.NullSelector.QualifiedName},");
            //     }
                
            //     TabOut("}", false);
            //     TabOut("}", false);
            //     Write("");
            // }

            TabOut("}");

            GenTpmStructureImplementation(s);

            GenGetUnionSelector(s);

            Write("");
        }

        void GenTpmStructureImplementation(TpmStruct s)
        {
            // Marshaling methods
            TabIn($"impl TpmStructure for {s.Name} {{");

            Write("/// Serialize this structure to a TPM buffer");
            TabIn("fn toTpm(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError> {");
            Write("self.serialize(buffer)");
            TabOut("}");
            Write("");

            Write("/// Deserialize this structure from a TPM buffer");
            TabIn("fn initFromTpm(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError> {");
            Write("self.deserialize(buffer)");
            TabOut("}");

            TabIn("fn fromTpm(&self, buf: &mut TpmBuffer) -> Result<(), TpmError> {");
            Write($"buf.createObj::<{s.Name}>();");
            Write("Ok(())");
            TabOut("}");

            TabIn("fn fromBytes(&self, buf: &mut Vec<u8>) -> Result<(), TpmError> {");
            Write($"self.initFromTpm(buf)");
            TabOut("}");

            GenStructMarshalingImpl(s);

            TabOut("}");
        }

        void GenerateTpmCommandPrototypes()
        {
            Write("//! TPM2 command implementations");
            Write("");
            Write("use crate::error::TpmError;");
            Write("use crate::tpm_buffer::TpmBuffer;");
            Write("use crate::tpm_types::*;");
            Write("");
            
            var commands = TpmTypes.Get<TpmStruct>().Where(s => s.Info.IsRequest());

            Write("/// Main TPM2 interface");
            Write("#[derive(Debug)]");
            TabIn("pub struct Tpm2 {");
            Write("// Implementation details");
            Write("device: crate::device::TpmDevice,");
            TabOut("}");
            Write("");
            
            TabIn("impl Tpm2 {");
            Write("/// Creates a new TPM2 instance");
            TabIn("pub fn new() -> Result<Self, TpmError> {");
            TabIn("Ok(Self {");
            Write("device: crate::device::TpmDevice::new()?,");
            TabOut("})");
            TabOut("}");
            Write("");

            Write("/// Main dispatch function for synchronous commands");
            TabIn("fn dispatch<Req: TpmStructure, Resp: TpmStructure>(&mut self, req: Req, resp: &mut Resp) -> Result<(), TpmError> {");
            Write("// Create buffer and marshal request");
            Write("let mut buffer = TpmBuffer::new();");
            Write("req.serialize(&mut buffer)?;");
            Write("");
            Write("// Send command to device");
            Write("let response_data = self.device.send_command(buffer.to_vec())?;");
            Write("");
            Write("// Parse response");
            Write("let mut resp_buffer = TpmBuffer::from(response_data);");
            Write("resp.deserialize(&mut resp_buffer)?;");
            Write("");
            Write("Ok(())");
            TabOut("}");
            Write("");
            
            Write("/// Dispatch function for asynchronous command phase");
            Write("fn dispatch_async_command<Req: TpmStructure>(&mut self, req: Req) -> Result<(), TpmError> {");
            TabIn("// Create buffer and marshal request");
            Write("let mut buffer = TpmBuffer::new();");
            Write("req.serialize(&mut buffer)?;");
            Write("");
            Write("// Send command to device");
            Write("self.device.send_async_command(buffer.to_vec())?;");
            Write("");
            Write("Ok(())");
            TabOut("}");
            Write("");
            
            Write("/// Dispatch function for asynchronous response phase");
            Write("fn dispatch_async_response<Resp: TpmStructure>(&mut self, resp: &mut Resp) -> Result<(), TpmError> {");
            TabIn("// Receive response from device");
            Write("let response_data = self.device.receive_async_response()?;");
            Write("");
            Write("// Parse response");
            Write("let mut resp_buffer = TpmBuffer::from(response_data);");
            Write("resp.deserialize(&mut resp_buffer)?;");
            Write("");
            Write("Ok(())");
            TabOut("}");
            Write("");
            
            foreach (TpmStruct s in commands)
                GenCommand(s, CommandFlavor.Synch);
                
            Write("/// Get async command methods");
            Write("pub fn async_methods(&mut self) -> AsyncMethods {");
            TabIn("AsyncMethods { tpm: self }");
            TabOut("}");
                
            TabOut("}");
            Write("");
            
            Write("/// Asynchronous TPM2 command methods");
            Write("pub struct AsyncMethods<'a> {");
            TabIn("tpm: &'a mut Tpm2,");
            TabOut("}");
            Write("");
            
            Write("impl<'a> AsyncMethods<'a> {");
            TabIn();
            
            foreach (TpmStruct s in commands)
                GenCommand(s, CommandFlavor.AsyncCommand);
                
            foreach (TpmStruct s in commands)
                GenCommand(s, CommandFlavor.AsyncResponse);
                
            TabOut("}");
        }

        enum CommandFlavor
        {
            Synch, AsyncCommand, AsyncResponse
        }

        void GenCommand(TpmStruct req, CommandFlavor gen)
        {
            var resp = GetRespStruct(req);
            var respFields = resp.NonTagFields;

            string cmdName = ToSnakeCase(GetCommandName(req));
            
            if (gen == CommandFlavor.AsyncCommand)
                cmdName += "_async";
            else if (gen == CommandFlavor.AsyncResponse)
                cmdName += "_complete";
                
            string annotation = Helpers.WrapText(AsSummary(req.Comment)) + eol;
            var reqFields = new StructField[0];
            if (gen != CommandFlavor.AsyncResponse)
            {
                reqFields = req.NonTagFields;
                foreach (var f in reqFields)
                    annotation += GetParamComment(f) + eol;
            }
            WriteComment(annotation + (GetReturnComment(resp.NonTagFields)), false);

            string returnType = GetCommandReturnType(gen, resp, cmdName, out string returnFieldName);
            
            Write($"pub fn {cmdName}(");
            TabIn();
            
            Write($"&mut self,");
            
            if (gen != CommandFlavor.AsyncResponse && reqFields.Length > 0)
            {
                foreach (var f in reqFields)
                {
                    if (f.MarshalType == MarshalType.ConstantValue)
                        continue;
                        
                    Write($"{ToSnakeCase(f.Name)}: {TransType(f)},");
                }
            }
            
            TabOut($") -> {returnType} {{");
            TabIn();
            if (gen == CommandFlavor.Synch)
            {
                Write("// Create request structure");
                if (reqFields.Length > 0)
                {
                    Write($"let req = {req.Name} {{");
                    TabIn();
                    foreach (var f in reqFields)
                    {
                        if (f.MarshalType == MarshalType.ConstantValue)
                            continue;
                            
                        Write($"{ToSnakeCase(f.Name)},");
                    }
                    TabOut("};");
                    Write("");
                }
                else
                {
                    Write($"let req = {req.Name}::default();");
                    Write("");
                }
                
                Write("// Send command and process response");

                if (respFields.Length > 0) {
                    Write($"let mut resp = {resp.Name}::default();");
                } else {
                    Console.WriteLine($"Used TPMS_EMPTY instead of {resp.Name}");
                    Write($"let mut resp = TPMS_EMPTY::default();");
                }

                Write("self.dispatch(req, &mut resp)?;");
                
                if (returnFieldName != null)
                {
                    Write($"Ok(resp.{ToSnakeCase(returnFieldName)})");
                }
                else if (respFields.Length > 0)
                {
                    Write("Ok(resp)");
                }
                else
                {
                    Write("Ok(())");
                }
            }
            else if (gen == CommandFlavor.AsyncCommand)
            {
                Write("// Create request structure and dispatch async command");
                if (reqFields.Length > 0)
                {
                    Write($"let req = {req.Name} {{");
                    TabIn();
                    foreach (var f in reqFields)
                    {
                        if (f.MarshalType == MarshalType.ConstantValue)
                            continue;
                            
                        Write($"{ToSnakeCase(f.Name)},");
                    }
                    TabOut("};");
                }
                else
                {
                    Write($"let req = {req.Name}::default();");
                }
                Write("self.tpm.dispatch_async_command(req)");
            }
            else // AsyncResponse
            {
                Write("// Complete async command by receiving and processing response");
                
                if (respFields.Length > 0)
                {
                    Write($"let mut resp = {resp.Name}::default();");
                }
                else
                {
                    Console.WriteLine($"Used TPMS_EMPTY instead of {resp.Name}");
                    Write($"let mut resp = TPMS_EMPTY::default();");
                }

                Write("self.tpm.dispatch_async_response(&mut resp)?;");
                
                if (returnFieldName != null)
                {
                    Write($"Ok(resp.{ToSnakeCase(returnFieldName)})");
                }
                else if (respFields.Length > 0)
                {
                    Write("Ok(resp)");
                }
                else
                {
                    Write("Ok(())");
                }
            }
            
            TabOut("}");
            Write("");
        }

        void GenEnumMap()
        {
            TabIn("lazy_static::lazy_static! {");
            Write("/// Maps enum type IDs to a map of values to string representations");
            Write("static ref ENUM_TO_STR_MAP: HashMap<std::any::TypeId, HashMap<u32, &'static str>> = {");
            TabIn("let mut map = HashMap::new();");
            
            foreach (var e in EnumMap)
            {
                var mutable = e.Value.Count > 0 ? "mut" : "";
                Write($"let {mutable} {ToSnakeCase(e.Key)}_map = HashMap::new();");
                foreach (var v in e.Value)
                {
                    Write($"{ToSnakeCase(e.Key)}_map.insert({v.Value}, \"{v.Key}\");");
                }
                Write($"map.insert(std::any::TypeId::of::<{e.Key}>(), {ToSnakeCase(e.Key)}_map);");
                Write("");
            }
            
            Write("map");
            TabOut("};");
            Write("");
            
            Write("/// Maps enum type IDs to a map of string representations to values");
            Write("static ref STR_TO_ENUM_MAP: HashMap<std::any::TypeId, HashMap<&'static str, u32>> = {");
            TabIn("let mut map = HashMap::new();");
            
            foreach (var e in EnumMap)
            {
                var mutable = e.Value.Count > 0 ? "mut" : "";
                Write($"let {mutable} {ToSnakeCase(e.Key)}_map = HashMap::new();");
                foreach (var v in e.Value)
                {
                    Write($"{ToSnakeCase(e.Key)}_map.insert(\"{v.Key}\", {v.Value});");
                }
                Write($"map.insert(std::any::TypeId::of::<{e.Key}>(), {ToSnakeCase(e.Key)}_map);");
                Write("");
            }
            
            Write("map");
            TabOut("};");
            TabOut("}");
            Write("");
        }

        void GenUnionFactory()
        {
            var unions = TpmTypes.Get<TpmUnion>().Where(u => u.Implement);

            WriteComment("Factory for creating TPM union types from selector values");
            Write("pub struct UnionFactory;");
            Write("");
            TabIn("impl UnionFactory {");
            Write("/// Creates a new union instance based on the selector value");
            TabIn("pub fn create<U: TpmUnion + ?Sized, S: TpmEnum>(selector: S) -> Result<Option<Box<dyn U>>, TpmError> {");
            Write("let type_id = std::any::TypeId::of::<U>();");
            Write("");
            
            foreach (TpmUnion u in unions)
            {
                TabIn($"if type_id == std::any::TypeId::of::<dyn {u.Name}>() {{");
                TabIn("match selector {");
                
                foreach (UnionMember m in u.Members)
                {
                    string memberName = ToRustEnumMemberName(m.Name);
                    if (m.Type.IsElementary())
                    {
                        Write($"{m.SelectorValue.QualifiedName} => Ok(Some(Box::new({u.Name}::{memberName}))),");
                    }
                    else
                    {
                        Write($"{m.SelectorValue.QualifiedName} => Ok(Some(Box::new({m.Type.Name}::default()) as Box<dyn U>)),");
                    }
                }
                
                Write("_ => Err(TpmError::InvalidUnion),");
                TabOut("}");
                TabOut("} else ");
            }
            
            TabIn("{");
            Write("Err(TpmError::InvalidUnion)");
            TabOut("}");
            
            TabOut("}");
            TabOut("}");
            Write("");
        }

        void GenStructMarshalingImpl(TpmStruct s)
        {
            var fields = s.MarshalFields;
            Write("// Implement serialization/deserialization");
            
            // To TPM implementation
            TabIn("fn serialize(&self, buf: &mut TpmBuffer) -> Result<(), TpmError> {");
            Write("// Serialize fields");
            var toTpmOps = GetToTpmFieldsMarshalOps(fields);

            foreach (var op in toTpmOps)
            {
                Write(op + ";");
            }
            Write("Ok(())");
            TabOut("}");
            Write("");

            // From TPM implementation
            TabIn("fn deserialize(&mut self, buf: &mut TpmBuffer) -> Result<(), TpmError> {");
            Write("// Deserialize fields");
            var fromTpmOps = CodeGenBase.GetFromTpmFieldsMarshalOps(s.MarshalFields);
            foreach (var op in fromTpmOps)
            {
                Write(op + ";");
            }
            Write("Ok(())");
            TabOut("}");
        }

        // Helper methods for Rust-specific formatting
        
        static string ToSnakeCase(string name)
        {
            return name;

            // if (string.IsNullOrEmpty(name))
            //     return name;
                
            // // Special case for single letter followed by uppercase
            // if (name.Length >= 2 && char.IsUpper(name[1]))
            //     return name;
                
            // // Insert underscores before uppercase letters
            // var result = Regex.Replace(name, "(?<=[a-z0-9])([A-Z])", "_$1");
            
            // // Handle acronyms (sequences of uppercase letters)
            // result = Regex.Replace(result, "([A-Z])([A-Z]+)", "$1$2");
            
            // return result;
        }
        
        /// <summary>
        /// Converts TPM enum values to Rust-compatible format, ensuring hexadecimal values
        /// are properly formatted according to Rust conventions.
        /// </summary>
        /// <returns>A properly formatted Rust-compatible value string</returns>
        static string ToRustEnumValue(TpmNamedConstant element)
        {
            // If no numeric value was caluclated, return the original value
            // if (element.NumericValue == null)
            // {
            //     return element.Value;
            // }

            return ToHex(element.NumericValue);
        }

        static string ToRustEnumMemberName(string name)
        {
            return name;
            // // For enum members, we want PascalCase format
            // if (string.IsNullOrEmpty(name))
            //     return name;
            
            // // First convert to snake_case if needed
            // if (name.contains("_"))
            // {
            //     // Split by underscore and capitalize each segment
            //     string[] parts = name.Split('_');
            //     for (int i = 0; i < parts.Length; i++)
            //     {
            //         if (!string.IsNullOrEmpty(parts[i]))
            //         {
            //             parts[i] = char.ToUpperInvariant(parts[i][0]) + 
            //                       (parts[i].Length > 1 ? parts[i].Substring(1).ToLowerInvariant() : "");
            //         }
            //     }
            //     return string.Join("", parts);
            // }
            // else
            // {
            //     // Just capitalize the first letter
            //     return char.ToUpperInvariant(name[0]) + 
            //           (name.Length > 1 ? name.Substring(1) : "");
            // }
        }
        
        
        string ConvertToRustInitVal(string cppInitVal)
        {
            // Handle common C++ init values
            switch (cppInitVal)
            {
                case "nullptr": return "None";
                case "0": return "0";
                case "true": return "true";
                case "false": return "false";
                default:
                    return cppInitVal;
            }
        }

        protected override void WriteComment(string comment, bool wrap = true)
        {
            WriteComment(comment, "/// ", "/// ", "", wrap);
        }

        // Helper methods for array handling and serialization
        
        /// <summary>
        /// Determines if a field is a list (vector/collection) by checking the type name
        /// </summary>
        private bool IsList(StructField f)
        {
            if (!f.IsArray())
                return false;
                
            // Check if it's a dynamic array/list (not a fixed size array)
            return f.Type.SpecName.StartsWith("TPML_") ||
                   (f.SizeTagField != null && f.SizeTagField.MarshalType == MarshalType.ArrayCount);
        }
        
        /// <summary>
        /// Gets the element type name for lists/arrays
        /// </summary>
        private string GetElementTypeName(StructField f)
        {
            if (f.Type.SpecName.StartsWith("TPML_"))
            {
                // Extract the element type from TPML_X (list of X)
                string elementTypeName = f.Type.SpecName.Substring(5);
                return elementTypeName;
            }
            
            // For regular arrays, use the base type
            return f.Type.SpecName;
        }
        
        /// <summary>
        /// Gets the size of an array if it's fixed size, or 0 if dynamic
        /// </summary>
        private int GetArraySize(StructField f)
        {
            if (!f.IsArray())
                return 0;
                
            // If there's a size tag field, it's a dynamic array
            if (f.SizeTagField != null && f.SizeTagField.MarshalType == MarshalType.ArrayCount)
                return 0;
                
            // Try to extract size from constraints if available
            if (f.MaxVal != null)
            {
                return (int)f.MaxVal.NumericValue;
            }
            
            // Default size for byte arrays if nothing else specified
            if (f.Type.SpecName == "BYTE")
                return 64;  // Common buffer size in TPM
                
            return 0;
        }
        
        /// <summary>
        /// Gets the base element type for use in lists/arrays
        /// </summary>
        private TpmType GetElementType(StructField f)
        {
            string elementTypeName = GetElementTypeName(f);
            return TpmTypes.Lookup(elementTypeName) ?? f.Type;
        }
    }
}
