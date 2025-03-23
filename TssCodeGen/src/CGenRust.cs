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

            GenerateTpmTypesImpl();
            UpdateExistingSource(@"src\tpm_types_impl.rs");
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
            if (f.MarshalType == MarshalType.UnionObject)
                return $"Option<Box<dyn {f.TypeName}>>";
            return ToSnakeCase(f.TypeName);
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
            Write("use std::convert::{TryFrom, TryInto};");
            Write("use std::fmt;");
            Write("");

            foreach (var e in TpmTypes.Get<TpmEnum>())
                GenEnum(e);

            foreach (var bf in TpmTypes.Get<TpmBitfield>())
                GenBitfield(bf);

            WriteComment("Base trait for TPM union types");
            Write("pub trait TpmUnion {");
            TabIn("/// Get the union selector value");
            Write("fn get_union_selector(&self) -> u32;");
            TabOut("}");
            Write("");

            foreach (var u in TpmTypes.Get<TpmUnion>())
                GenUnion(u);

            foreach (var s in TpmTypes.Get<TpmStruct>())
                GenStructDecl(s);
        }

        void GenEnum(TpmType e, List<TpmNamedConstant> elements)
        {
            WriteComment(e);
            Write($"#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]");
            Write($"#[repr(u{e.GetFinalUnderlyingType().GetSize() * 8})]");
            Write($"pub enum {e.Name} {{");
            TabIn();

            var enumVals = new Dictionary<string, string>();
            foreach (var elt in elements)
            {
                WriteComment(AsSummary(elt.Comment));
                string delimiter = Separator(elt, elements).Replace(",", ",");
                Write($"{ToRustEnumMemberName(elt.Name)} = {elt.Value}{delimiter}");

                // Do not include artificially added named constants into the name conversion maps
                if (elt.SpecName != null)
                    enumVals[elt.Name] = e is TpmEnum ? ToHex(elt.NumericValue) : elt.Value;
            }
            TabOut("}");

            // Implement TryFrom for numeric conversion
            Write("");
            TabIn($"impl TryFrom<u{e.GetFinalUnderlyingType().GetSize() * 8}> for {e.Name} {{");
            Write("type Error = TpmError;");
            Write("");
            TabIn($"fn try_from(value: u{e.GetFinalUnderlyingType().GetSize() * 8}) -> Result<Self, Self::Error> {{");
            TabIn("match value {");
            foreach (var elt in elements)
            {
                Write($"{elt.Value} => Ok(Self::{ToRustEnumMemberName(elt.Name)}),");
            }
            Write("_ => Err(TpmError::InvalidEnumValue),");
            TabOut("}");
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
            TabOut("}");
            TabOut("}");
            TabOut("}");
            Write("");
            
            EnumMap[e.Name] = enumVals;
        }

        void GenEnum(TpmEnum e)
        {
            GenEnum(e, e.Members);
        }

        void GenBitfield(TpmBitfield bf)
        {
            GenEnum(bf, GetBifieldElements(bf));

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

        void GenUnion(TpmUnion u)
        {
            if (!u.Implement)
                return;

            WriteComment(u);
            Write($"pub enum {u.Name} {{");
            TabIn();
            
            foreach (var m in u.Members)
            {
                if (m.Type.IsElementary())
                {
                    Write($"{ToRustEnumMemberName(m.Name)},");
                }
                else 
                {
                    Write($"{ToRustEnumMemberName(m.Name)}({m.Type.Name}),");
                }
            }
            
            TabOut("}");
            Write("");
            
            TabIn($"impl TpmUnion for {u.Name} {{");
            TabIn("fn get_union_selector(&self) -> u32 {");
            TabIn("match self {");
            
            foreach (var m in u.Members)
            {
                string memberName = ToRustEnumMemberName(m.Name);
                if (m.Type.IsElementary())
                {
                    Write($"Self::{memberName} => {m.SelectorValue.QualifiedName.Replace("::", ":")} as u32,");
                }
                else
                {
                    Write($"Self::{memberName}(_) => {m.SelectorValue.QualifiedName.Replace("::", ":")} as u32,");
                }
            }
            
            TabOut("}");
            TabOut("}");
            TabOut("}");
            Write("");

            // Implement Debug trait
            TabIn($"impl fmt::Debug for {u.Name} {{");
            TabIn("fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {");
            TabIn("match self {");
            foreach (var m in u.Members)
            {
                string memberName = ToRustEnumMemberName(m.Name);
                if (m.Type.IsElementary())
                {
                    Write($"Self::{memberName} => write!(f, \"{u.Name}::{memberName}\"),");
                }
                else
                {
                    Write($"Self::{memberName}(inner) => write!(f, \"{u.Name}::{memberName}({{:?}})\", inner),");
                }
            }
            TabOut("}");
            TabOut("}");
            TabOut("}");
            Write("");
        }

        string GetUnionSelectorType(TpmUnion u)
        {
            // Take the type from the first member's selector value if available
            if (u.Members.Count > 0)
            {
                var firstMember = u.Members.First();
                return firstMember.SelectorValue.EnclosingEnum.Name;
            }
            return "u32"; // Default
        }

        string GetUnionMemberSelectorInfo(TpmStruct s, out string selVal)
        {
            selVal = null;
            if (s.ContainingUnions.Count == 0)
                return null;

            // Find the containing union and the corresponding member
            var union = s.ContainingUnions.First();
            var member = union.Members.FirstOrDefault(m => m.Type.SpecName == s.SpecName);
            if (member == null)
                return null;

            selVal = $"{union.Name}::{ToRustEnumMemberName(member.SelectorValue.Name)}";
            return GetUnionSelectorType(union);
        }

        void GenGetUnionSelector(TpmStruct s)
        {
            string selType = GetUnionMemberSelectorInfo(s, out string selVal);
            if (selType != null)
            {
                WriteComment("TpmUnion trait implementation");
                Write("fn get_union_selector(&self) -> u32 {");
                TabIn($"{selVal} as u32");
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
            Write($"#[derive(Debug, Clone)]");
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
            
            // Default implementation
            TabIn($"impl Default for {structName} {{");
            TabIn("fn default() -> Self {");
            TabIn("Self {");
            
            var fieldsToInit = s.NonDefaultInitFields;
            if (fieldsToInit.Count() != 0)
            {
                foreach (StructField f in fieldsToInit)
                    Write($"{f.Name} = {f.GetInitVal()};");
            }

            // foreach (var f in s.NonSizeFields)
            // {
            //     if (f.MarshalType == MarshalType.ConstantValue || f.MarshalType == MarshalType.UnionSelector)
            //         continue;
                    
            //     string defaultValue = GetRustDefaultValue(f);
            //     Write($"{ToSnakeCase(f.Name)}: {defaultValue},");
            // }
            
            TabOut("}");
            TabOut("}");
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
                
                bool first = true;
                foreach (var f in s.NonTagFields)
                {
                    if (f.MarshalType == MarshalType.ConstantValue || f.MarshalType == MarshalType.UnionSelector)
                        continue;
                        
                    if (!first)
                        Write(",");
                    Write($"{ToSnakeCase(f.Name)}: {TransType(f)}");
                    first = false;
                }
                
                Write($") -> Self {{");
                TabIn("Self {");
                
                foreach (var f in s.NonTagFields)
                {
                    if (f.MarshalType == MarshalType.ConstantValue || f.MarshalType == MarshalType.UnionSelector)
                        continue;
                        
                    Write($"{ToSnakeCase(f.Name)},");
                }
                
                TabOut("}");
                TabOut("}");
                Write("");
            }
            
            // Selector methods for unions
            foreach (var f in s.Fields.Where(f => f.MarshalType == MarshalType.UnionSelector))
            {
                var unionField = f.RelatedUnion;
                var u = (TpmUnion)unionField.Type;
                
                Write($"/// Get the {f.Name} selector value");
                Write($"pub fn {ToSnakeCase(f.Name)}(&self) -> {f.TypeName} {{");
                TabIn();
                
                if (u.NullSelector == null)
                {
                    Write($"match &self.{ToSnakeCase(unionField.Name)} {{");
                    TabIn("Some(u) => u.get_union_selector() as _,");
                    Write("None => 0 as _,");
                    TabOut("}");
                }
                else
                {
                    Write($"match &self.{ToSnakeCase(unionField.Name)} {{");
                    TabIn("Some(u) => u.get_union_selector() as _,");
                    Write($"None => {u.NullSelector.QualifiedName.Replace("::", ":")} as _,");
                    TabOut("}");
                }
                
                TabOut("}");
                Write("");
            }

            // Implement TpmUnion trait if needed
            if (s.ContainingUnions?.Count > 0)
            {
                Write("// Union trait implementations");
                foreach (var u in s.ContainingUnions)
                {
                    Write($"impl TpmUnion for {structName} {{");
                    TabIn();
                    GenGetUnionSelector(s);
                    TabOut("}");
                }
                Write("");
            }
            
            // Marshaling methods
            Write("/// Serialize this structure to a TPM buffer");
            Write("pub fn to_tpm(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError> {");
            TabIn("// Implement serialization");
            Write("Ok(())");
            TabOut("}");
            Write("");
            
            Write("/// Deserialize this structure from a TPM buffer");
            Write("pub fn from_tpm(buffer: &mut TpmBuffer) -> Result<Self, TpmError> {");
            TabIn("// Implement deserialization");
            Write("Ok(Self::default())");
            TabOut("}");

            TabOut("}");
            Write("");
        }

        void GenerateTpmCommandPrototypes()
        {
            Write("//! TPM2 command implementations");
            Write("");
            Write("use crate::error::TpmError;");
            Write("use crate::tpm_buffer::TpmBuffer;");
            Write("use crate::tpm_types::*;");
            Write("use std::convert::TryInto;");
            Write("");
            
            var commands = TpmTypes.Get<TpmStruct>().Where(s => s.Info.IsRequest());

            Write("/// Main TPM2 interface");
            Write("#[derive(Debug)]");
            Write("pub struct Tpm2 {");
            TabIn("// Implementation details");
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
            
            if (gen == CommandFlavor.Synch)
            {
                TabIn("// Create request structure");
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
                Write($"let mut resp = {resp.Name}::default();");
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
                TabIn("// Create request structure and dispatch async command");
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
                TabIn("// Complete async command by receiving and processing response");
                Write($"let mut resp = {resp.Name}::default();");
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

        void GenerateTpmTypesImpl()
        {
            Write("//! TPM types implementation");
            Write("");
            Write("use crate::error::TpmError;");
            Write("use crate::tpm_buffer::TpmBuffer;");
            Write("use crate::tpm_types::*;");
            Write("use std::collections::HashMap;");
            Write("use std::convert::TryFrom;");
            Write("");
            
            GenEnumMap();
            GenUnionFactory();
            GenStructsImpl();
            GenCommandDispatchers();
        }

        void GenEnumMap()
        {
            Write("lazy_static::lazy_static! {");
            TabIn("/// Maps enum type IDs to a map of values to string representations");
            Write("static ref ENUM_TO_STR_MAP: HashMap<std::any::TypeId, HashMap<u32, &'static str>> = {");
            TabIn("let mut map = HashMap::new();");
            
            foreach (var e in EnumMap)
            {
                Write($"let mut {ToSnakeCase(e.Key)}_map = HashMap::new();");
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
                Write($"let mut {ToSnakeCase(e.Key)}_map = HashMap::new();");
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
            Write("impl UnionFactory {");
            TabIn("/// Creates a new union instance based on the selector value");
            Write("pub fn create<U: TpmUnion>(selector: u32) -> Option<Box<dyn TpmUnion>> {");
            TabIn("let type_id = std::any::TypeId::of::<U>();");
            Write("");
            
            foreach (TpmUnion u in unions)
            {
                TabIn($"if type_id == std::any::TypeId::of::<{u.Name}>() {{");
                TabIn("match selector {");
                
                foreach (UnionMember m in u.Members)
                {
                    string memberName = ToRustEnumMemberName(m.Name);
                    if (m.Type.IsElementary())
                    {
                        Write($"{m.SelectorValue.QualifiedName.Replace("::", ":")} as u32 => Some(Box::new({u.Name}::{memberName})),");
                    }
                    else
                    {
                        Write($"{m.SelectorValue.QualifiedName.Replace("::", ":")} as u32 => Some(Box::new({u.Name}::{memberName}({m.Type.Name}::default()))),");
                    }
                }
                
                Write("_ => None,");
                TabOut("}");
                TabOut("} else ");
            }
            
            Write("{");
            TabIn("None");
            TabOut("}");
            
            TabOut("}");
            TabOut("}");
            Write("");
        }

        void GenStructsImpl()
        {
            foreach (var s in TpmTypes.Get<TpmStruct>())
            {
                if (IsTypedefStruct(s))
                    continue;
                    
                GenStructMarshalingImpl(s);
            }
        }

        void GenStructMarshalingImpl(TpmStruct s)
        {
            Write($"impl {s.Name} {{");
            TabIn("// Implement serialization/deserialization");
            
            // To TPM implementation
            Write("fn serialize(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError> {");
            TabIn("// Serialize fields");
            foreach (var f in s.MarshalFields)
            {
                if (f.MarshalType == MarshalType.ConstantValue)
                {
                    Write($"// Constant value: {ConstTag(f)}");
                    continue;
                }
                
                if (f.Type.IsElementary())
                {
                    int size = f.Type.GetSize();
                    Write($"buffer.write_u{size * 8}(self.{ToSnakeCase(f.Name)})?;");
                }
                else if (f.IsEnum())
                {
                    Write($"buffer.write_u32(self.{ToSnakeCase(f.Name)} as u32)?;");
                }
                else if (f.MarshalType == MarshalType.UnionObject)
                {
                    Write($"if let Some(union_obj) = &self.{ToSnakeCase(f.Name)} {{");
                    TabIn("buffer.write_union(union_obj.as_ref())?;");
                    TabOut("}");
                }
                else if (f.IsByteBuffer())
                {
                    Write($"buffer.write_sized_buffer(&self.{ToSnakeCase(f.Name)})?;");
                }
                else if (f.IsArray())
                {
                    Write($"buffer.write_sized_array(&self.{ToSnakeCase(f.Name)})?;");
                }
                else
                {
                    Write($"self.{ToSnakeCase(f.Name)}.serialize(buffer)?;");
                }
            }
            Write("Ok(())");
            TabOut("}");
            Write("");
            
            // From TPM implementation
            Write("fn deserialize(&mut self, buffer: &mut TpmBuffer) -> Result<(), TpmError> {");
            TabIn("// Deserialize fields");
            foreach (var f in s.MarshalFields)
            {
                if (f.MarshalType == MarshalType.ConstantValue)
                {
                    Write($"// Constant value: {ConstTag(f)}");
                    continue;
                }
                
                if (f.Type.IsElementary())
                {
                    int size = f.Type.GetSize();
                    Write($"self.{ToSnakeCase(f.Name)} = buffer.read_u{size * 8}()?;");
                }
                else if (f.IsEnum())
                {
                    Write($"self.{ToSnakeCase(f.Name)} = {f.TypeName}::try_from(buffer.read_u32()?)?;");
                }
                else if (f.MarshalType == MarshalType.UnionObject)
                {
                    var unionField = f as UnionField;
                    var selectorField = unionField.UnionSelector;
                    Write($"let selector = self.{ToSnakeCase(selectorField.Name)}();");
                    Write($"self.{ToSnakeCase(f.Name)} = if selector != 0 {{");
                    TabIn($"let mut obj = UnionFactory::create::<{f.TypeName}>(selector as u32)");
                    Write(".ok_or(TpmError::InvalidUnion)?;");
                    Write("buffer.read_union(obj.as_mut())?;");
                    Write("Some(obj)");
                    TabOut("} else {");
                    TabIn("None");
                    TabOut("};");
                }
                else if (f.IsByteBuffer())
                {
                    Write($"self.{ToSnakeCase(f.Name)} = buffer.read_sized_buffer()?;");
                }
                else if (f.IsArray())
                {
                    Write($"self.{ToSnakeCase(f.Name)} = buffer.read_sized_array()?;");
                }
                else
                {
                    Write($"self.{ToSnakeCase(f.Name)}.deserialize(buffer)?;");
                }
            }
            Write("Ok(())");
            TabOut("}");
            
            TabOut("}");
            Write("");
        }

        void GenCommandDispatchers()
        {
            var cmdRequestStructs = TpmTypes.Get<TpmStruct>().Where(s => s.Info.IsRequest());

            Write("impl Tpm2 {");
            TabIn("/// Main dispatch function for synchronous commands");
            Write("fn dispatch<Req: TpmStructure, Resp: TpmStructure>(&mut self, req: Req, resp: &mut Resp) -> Result<(), TpmError> {");
            TabIn("// Create buffer and marshal request");
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
            
            TabOut("}");
            Write("");
            
            Write("/// Trait for structures that can be marshaled to/from TPM wire format");
            Write("pub trait TpmStructure: Sized {");
            TabIn("/// Serialize the structure to a TPM buffer");
            Write("fn serialize(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError>;");
            Write("");
            Write("/// Deserialize the structure from a TPM buffer");
            Write("fn deserialize(&mut self, buffer: &mut TpmBuffer) -> Result<(), TpmError>;");
            TabOut("}");
            Write("");
            
            // Implement TpmStructure for all generated structs
            Write("// Implement TpmStructure trait for all TPM structs");
            foreach (var s in TpmTypes.Get<TpmStruct>())
            {
                if (!IsTypedefStruct(s))
                {
                    Write($"impl TpmStructure for {s.Name} {{");
                    TabIn("fn serialize(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError> {");
                    TabIn("self.serialize(buffer)");
                    TabOut("}");
                    Write("");
                    Write("fn deserialize(&mut self, buffer: &mut TpmBuffer) -> Result<(), TpmError> {");
                    TabIn("self.deserialize(buffer)");
                    TabOut("}");
                    TabOut("}");
                    Write("");
                }
            }
        }
        
        // Helper methods for Rust-specific formatting
        
        static string ToSnakeCase(string name)
        {
            if (string.IsNullOrEmpty(name))
                return name;
                
            // Special case for single letter followed by uppercase
            if (name.Length >= 2 && char.IsUpper(name[1]))
                return name.ToLowerInvariant();
                
            // Insert underscores before uppercase letters
            var result = Regex.Replace(name, "(?<=[a-z0-9])([A-Z])", "_$1").ToLowerInvariant();
            
            // Handle acronyms (sequences of uppercase letters)
            result = Regex.Replace(result, "([A-Z])([A-Z]+)", "$1$2").ToLowerInvariant();
            
            return result;
        }
        
        static string ToRustEnumMemberName(string name)
        {
            // For enum members, we want PascalCase format
            if (string.IsNullOrEmpty(name))
                return name;
            
            // First convert to snake_case if needed
            if (name.Contains("_"))
            {
                // Split by underscore and capitalize each segment
                string[] parts = name.Split('_');
                for (int i = 0; i < parts.Length; i++)
                {
                    if (!string.IsNullOrEmpty(parts[i]))
                    {
                        parts[i] = char.ToUpperInvariant(parts[i][0]) + 
                                  (parts[i].Length > 1 ? parts[i].Substring(1).ToLowerInvariant() : "");
                    }
                }
                return string.Join("", parts);
            }
            else
            {
                // Just capitalize the first letter
                return char.ToUpperInvariant(name[0]) + 
                      (name.Length > 1 ? name.Substring(1) : "");
            }
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
                    // Check for enum values
                    if (cppInitVal.Contains("::"))
                        return cppInitVal.Replace("::", ":");
                    return cppInitVal;
            }
        }

        protected override void WriteComment(string comment, bool wrap = true)
        {
            WriteComment(comment, "/// ", "/// ", "", wrap);
        }
    }
}
