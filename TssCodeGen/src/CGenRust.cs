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
        static readonly (string, string)[] TpmStructureFunctions = new (string, string)[] {
            ("serialize", "(&self, buffer: &mut TpmBuffer)"),
            ("deserialize", "(&mut self, buffer: &mut TpmBuffer)"),
            ("fromTpm", "(&self, buffer: &mut TpmBuffer)"),
            ("fromBytes", "(&mut self, buffer: &mut Vec<u8>)"),
        };
        
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
                return $"Option<{ToSnakeCase(typeName)}>";
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
            
            var enumUnderlyingType = e.GetFinalUnderlyingType();
            var sizeInBits = enumUnderlyingType.GetSize() * 8;
            var enumUnderlyingTypeName = enumUnderlyingType.Name;
            var enumUnderlyingTypeSigned = enumUnderlyingTypeName.StartsWith("i") ? true : false;
            
            if (hasDuplicates)
            {
                // Generate a newtype struct with constants for enums with duplicates
                WriteComment("Enum with duplicated values - using struct with constants");
                Write($"#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]");
                Write($"pub struct {e.Name}(pub {enumUnderlyingTypeName});");
                Write("");
                
                // Generate constants for each enum value
                TabIn($"impl {e.Name} {{");
                
                foreach (var elt in elements)
                {
                    WriteComment(AsSummary(elt.Comment));
                    var enumValue = ToRustEnumValue(elt, sizeInBits, enumUnderlyingTypeSigned);
                    var enumHexValue = enumUnderlyingTypeSigned ? enumValue.ToString() : ToHex(enumValue);
                    var originalValueComment = "";
                    if (enumHexValue != elt.Value)
                    {
                        originalValueComment = $" // Original value: {elt.Value}";
                    }
                    
                    Write($"pub const {elt.Name}: Self = Self({enumHexValue});{originalValueComment}");
                    
                    // Do not include artificially added named constants into the name conversion maps
                    if (elt.SpecName != null)
                        enumVals[elt.Name] = e is TpmEnum ? ToHex(elt.NumericValue) : elt.Value;
                }
                
                // Add TryFrom implementation for the newtype struct
                Write("");
                TabIn($"pub fn try_from(value: {enumUnderlyingTypeName}) -> Result<Self, TpmError> {{");
                TabIn("match value {");
                foreach (var elt in elements.GroupBy(x => x.NumericValue).Select(g => g.First()))
                {
                    var enumValue = ToRustEnumValue(elt, sizeInBits, enumUnderlyingTypeSigned);

                    // Only include first occurrence of each value to avoid duplicate match arms
                    Write($"{enumValue} => Ok(Self::{elt.Name}), // Original value: {elt.Value}");
                }
                Write("_ => Err(TpmError::InvalidEnumValue),");
                TabOut("}", false);
                TabOut("}", false);
                
                TabOut("}");
                Write("");
                
                // Implement TpmEnum trait for the struct
                TabIn($"impl TpmEnum<{enumUnderlyingTypeName}> for {e.Name} {{");
                TabIn($"fn get_value(&self) -> {enumUnderlyingTypeName} {{");
                Write("self.0.into()");
                TabOut("}");
                TabIn("fn try_from_trait(value: u64) -> Result<Self, TpmError> where Self: Sized {");
                Write($"{e.Name}::try_from(value as {enumUnderlyingTypeName})");
                TabOut("}", false);
                TabOut("}");
                Write("");
                
                // Add numeric conversions
                TabIn($"impl From<{e.Name}> for u{sizeInBits} {{");
                TabIn($"fn from(value: {e.Name}) -> Self {{");
                Write("value.0.into()");
                TabOut("}", false);
                TabOut("}");
                Write("");
                
                TabIn($"impl From<{e.Name}> for i{sizeInBits} {{");
                TabIn($"fn from(value: {e.Name}) -> Self {{");
                Write($"value.0 as i{sizeInBits} ");
                TabOut("}", false);
                TabOut("}");
                Write("");
                               
                // Implement Display trait
                TabIn($"impl fmt::Display for {e.Name} {{");
                TabIn("fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {");
                TabIn("match self.0 {");
                
                // Group by value to avoid duplicate match arms
                var grouped = elements.GroupBy(x => ToRustEnumValue(x, sizeInBits, enumUnderlyingTypeSigned));
                foreach (var group in grouped)
                {
                    if (group.Count() == 1)
                    {
                        // Only one variant for this value
                        Write($"{group.Key} => write!(f, \"{group.First().Name}\"),");
                    }
                    else
                    {
                        // Multiple variants for this value
                        var variants = group.Select(elt => elt.Name);
                        Write($"{group.Key} => write!(f, \"One of <{string.Join(", ", variants)}>\"),");
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
                Write($"#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]");
                Write($"#[repr({enumUnderlyingTypeName})]");
                Write($"pub enum {e.Name} {{");
                TabIn();

                Write("#[default]");
                foreach (var elt in elements)
                {
                    WriteComment(AsSummary(elt.Comment));
                    string delimiter = Separator(elt, elements).Replace(",", ",");

                    var enumValue = ToRustEnumValue(elt, sizeInBits, enumUnderlyingTypeSigned);
                    var enumHexValue = enumUnderlyingTypeSigned ? enumValue.ToString() : ToHex(enumValue);
                    var originalValueComment = "";
                    if (enumHexValue != elt.Value)
                    {
                        originalValueComment = $" // Original value: {elt.Value}";
                    }

                    Write($"{ToRustEnumMemberName(elt.Name)} = {enumHexValue}{delimiter}{originalValueComment}");

                    // Do not include artificially added named constants into the name conversion maps
                    if (elt.SpecName != null)
                        enumVals[elt.Name] = e is TpmEnum ? ToHex(elt.NumericValue) : elt.Value;
                }
                TabOut("}");
                
                TabIn($"impl {e.Name} {{");
                // Add TryFrom implementation for the newtype struct
                TabIn($"pub fn try_from(value: {enumUnderlyingTypeName}) -> Result<Self, TpmError> {{");
                TabIn("match value {");

                foreach (var elt in elements.GroupBy(x => ToRustEnumValue(x, sizeInBits, enumUnderlyingTypeSigned))
                                            .Select(g => g.First()))
                {
                    var enumValue = ToRustEnumValue(elt, sizeInBits, enumUnderlyingTypeSigned);
                    // Only include first occurrence of each value to avoid duplicate match arms
                    Write($"{enumValue} => Ok(Self::{elt.Name}), // Original value: {elt.Value}");
                }
                Write("_ => Err(TpmError::InvalidEnumValue),");
                TabOut("}");
                TabOut("}");
                TabOut("}");
                

                // Implement TpmEnum trait for the enum
                TabIn($"impl TpmEnum<{enumUnderlyingTypeName}> for {e.Name} {{");
                TabIn($"fn get_value(&self) -> {enumUnderlyingTypeName} {{");
                Write($"*self as {enumUnderlyingTypeName}");
                TabOut("}");
                TabIn($"fn try_from_trait(value: u64) -> Result<Self, TpmError> where Self: Sized {{");
                Write($"{e.Name}::try_from(value as {enumUnderlyingTypeName}).map_err(|_| TpmError::InvalidEnumValue)");
                TabOut("}", false);
                TabOut("}");
                Write("");
                
                // Add numeric conversions
                TabIn($"impl From<{e.Name}> for u{sizeInBits} {{");
                TabIn($"fn from(value: {e.Name}) -> Self {{");
                Write($"value as u{sizeInBits}");
                TabOut("}");
                TabOut("}");
                Write("");
                
                TabIn($"impl From<{e.Name}> for i{sizeInBits} {{");
                TabIn($"fn from(value: {e.Name}) -> Self {{");
                Write($"value as i{sizeInBits}");
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

            var unionSelectorType = GetUnionSelectorType(u);

            WriteComment(u);

            Write($"#[derive(Clone)]");
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

            WriteComment("Union selector type");
            TabIn($"impl {u.Name} {{");
            TabIn($"pub fn GetUnionSelector(&self) -> {unionSelectorType} {{");
            TabIn("match self {");
            foreach (var m in u.Members)
            {
                string memberName = ToRustEnumMemberName(m.Name);
                if (m.Type.IsElementary())
                {
                    Write($"Self::{memberName} => {m.SelectorValue.QualifiedName}, ");
                }
                else
                {
                    Write($"Self::{memberName}(_) => {m.Type.Name}::GetUnionSelector(),");
                }
            }
            TabOut("}", false);
            TabOut("}");

            TabIn($"fn create(selector: {unionSelectorType}) -> Result<Option<Self>, TpmError> {{");
            TabIn("match selector {");
            foreach (var m in u.Members)
            {
                string memberName = ToRustEnumMemberName(m.Name);
                if (m.Type.IsElementary())
                {
                    Write($"{m.SelectorValue.QualifiedName} => Ok(None),");
                }
                else
                {
                    Write($"{m.SelectorValue.QualifiedName} => Ok(Some(Self::{memberName}({m.Type.Name}::default()))),");
                }

            }
            Write("_ => Err(TpmError::InvalidUnion),");
            
            TabOut("}", false);
            TabOut("}", false);
            
            TabOut("}");

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
            TabOut("}", false);
            TabOut("}", false);
            TabOut("}", false);

            // Marshaling methods
            TabIn($"impl TpmStructure for {u.Name} {{");

            foreach (var functionNameAndParams in TpmStructureFunctions)
            {
                TabIn("fn " + functionNameAndParams.Item1 + functionNameAndParams.Item2 + " -> Result<(), TpmError> {");
                TabIn("match self {");
                foreach (var m in u.Members)
                {
                    string memberName = ToRustEnumMemberName(m.Name);
                    if (m.Type.IsElementary())
                    {
                        Write($"Self::{memberName} => Ok(()),");
                    }
                    else 
                    {
                        Write($"Self::{memberName}(inner) => inner.{functionNameAndParams.Item1}(buffer),");
                    }
                }
                TabOut("}", false);
                TabOut("}");
            }

            TabOut("}");

            TabIn($"impl TpmMarshaller for {u.Name} {{");
            var tpmMarshallerFunctions = new (string, string)[] {
                ("toTpm", "(&self, buffer: &mut TpmBuffer)"),
                ("initFromTpm", "(&mut self, buffer: &mut TpmBuffer)"),
            };

            foreach (var functionNameAndParams in tpmMarshallerFunctions)
            {
                TabIn("fn " + functionNameAndParams.Item1 + functionNameAndParams.Item2 + " -> Result<(), TpmError> {");
                TabIn("match self {");
                foreach (var m in u.Members)
                {
                    string memberName = ToRustEnumMemberName(m.Name);
                    if (m.Type.IsElementary())
                    {
                        Write($"Self::{memberName} => Ok(()),");
                    }
                    else 
                    {
                        Write($"Self::{memberName}(inner) => inner.{functionNameAndParams.Item1}(buffer),");
                    }
                }
                TabOut("}", false);
                TabOut("}");
            }

            TabOut("}");
            
            Write("");
        }
            
        void GenGetUnionSelector(TpmStruct s)
        {
            string selType = GetUnionMemberSelectorInfo(s, out string selVal);
            if (selType == null)
            {
                return;
            }

            TabIn($"fn GetUnionSelector() -> {selType} {{");
            Write($"{selVal}");
            TabOut("}", false);
        }

        void GenStructDecl(TpmStruct s)
        {
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
            Write($"#[derive(Debug, Default, Clone)]");
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

            GenGetUnionSelector(s);

            TabOut("}");

            GenTpmStructureImplementation(s);

            GenTpmMarshallerImplementation(s);

            GenTpmCmdStructureImplementation(s);

            Write("");
        }

        void GenTpmStructureImplementation(TpmStruct s)
        {
            // Marshaling methods
            TabIn($"impl TpmStructure for {s.Name} {{");

            TabIn("fn fromTpm(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError> {");
            Write($"buffer.createObj::<{s.Name}>();");
            Write("Ok(())");
            TabOut("}");

            TabIn("fn fromBytes(&mut self, buffer: &mut Vec<u8>) -> Result<(), TpmError> {");
            Write("let mut tpm_buffer = TpmBuffer::from(buffer);");
            Write($"self.initFromTpm(&mut tpm_buffer)");
            TabOut("}");

            GenStructMarshalingImpl(s);

            TabOut("}");
        }

        void GenTpmMarshallerImplementation(TpmStruct s)
        {
            // Marshaling methods
            TabIn($"impl TpmMarshaller for {s.Name} {{");

            Write("/// Serialize this structure to a TPM buffer");
            TabIn("fn toTpm(&self, buffer: &mut TpmBuffer) -> Result<(), TpmError> {");
            Write("self.serialize(buffer)");
            TabOut("}");
            Write("");

            Write("/// Deserialize this structure from a TPM buffer");
            TabIn("fn initFromTpm(&mut self, buffer: &mut TpmBuffer) -> Result<(), TpmError> {");
            Write("self.deserialize(buffer)");
            TabOut("}");

            TabOut("}");
        }

        void GenTpmCmdStructureImplementation(TpmStruct s)
        {
            var info = s.IsCmdStruct() ? s.Info as CmdStructInfo : null;

            if (info == null) {
                return;
            }

            TabIn($"impl CmdStructure for {s.Name} {{");

            Write($"fn num_handles(&self) -> u16 {{ {info.NumHandles} }}");
            Write("");

            if (info.SessEncSizeLen != 0)
            {
                Debug.Assert(info.SessEncValLen != 0);
                Write($"fn sess_enc_info(&self) -> SessEncInfo {{ SessEncInfo {{ sizeLen: {info.SessEncSizeLen}, valLen: {info.SessEncValLen} }} }}");
            }

            TabOut("}");

            // if (info.NumHandles == 0)
            // {
            //     return;
            // }

            if (info.IsRequest()) {
                GenReqStructureImplementation(s, info);
            } else {
                GenRespStructureImplementation(s, info);
            }
        }

        private void GenRespStructureImplementation(TpmStruct s, CmdStructInfo info)
        {
            TabIn($"impl RespStructure for {s.Name} {{");

            if (info.NumHandles == 0)
            {
                Write($"fn get_handle(&self) -> TPM_HANDLE {{ TPM_HANDLE::default() }}");
                Write("");
                Write($"fn set_handle(&mut self, _handle: &TPM_HANDLE) {{ }}");
            } else {
                Write($"fn get_handle(&self) -> TPM_HANDLE {{ self.{s.Fields[0].Name}.clone() }}");
                Write("");
                Write($"fn set_handle(&mut self, handle: &TPM_HANDLE) {{ self.{s.Fields[0].Name} = handle.clone(); }}");
            }

            TabOut("}");
        }

        private void GenReqStructureImplementation(TpmStruct s, CmdStructInfo info)
        {
            string handles = string.Join(", ", s.Fields.Take(info.NumHandles).Select(f => "self." + f.Name + ".clone()"));

            TabIn($"impl ReqStructure for {s.Name} {{");

            Write($"fn num_auth_handles(&self) -> u16 {{ {info.NumAuthHandles} }}");
            Write("");
            Write($"fn get_handles(&self) ->  Vec<TPM_HANDLE> {{ vec![{handles}] }}");

            TabOut("}");
        }

        void GenerateTpmCommandPrototypes()
        {
            var commands = TpmTypes.Get<TpmStruct>().Where(s => s.Info.IsRequest());

            TabIn("impl Tpm2 {");
            
            foreach (TpmStruct s in commands)
                GenCommand(s, CommandFlavor.Synch);

            TabOut("}");
            Write("");
            
            Write("/// Asynchronous TPM2 command methods");
            TabIn("pub struct AsyncMethods<'a> {");
            Write("tpm: &'a mut Tpm2,");
            TabOut("}");
            Write("");
            
            TabIn("impl<'a> AsyncMethods<'a> {");
            Write("");
            
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
            string cmdCode = "TPM_CC::" + cmdName;
            
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
            GenCommandImplementation(req, resp, reqFields, returnFieldName, gen);
            TabOut("}");
            Write("");
        }

        private void GenCommandImplementation(TpmStruct req, TpmStruct resp, StructField[] reqFields, string returnFieldName, CommandFlavor gen)
        {
            // Create request structure
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
            else if (gen != CommandFlavor.AsyncResponse)
            {
                Write($"let req = {req.Name}::default();");
                Write("");
            }

            var respFields = resp.NonTagFields;
            // Create response structure (or empty if there is no response)
            if (respFields.Length > 0)
            {
                Write($"let mut resp = {resp.Name}::default();");
            }
            else
            {
                Write($"let mut resp = EmptyTpmResponse::default();");
            }

            // Call dispatch method
            var cmdCode = "TPM_CC::" + ToSnakeCase(GetCommandName(req));
            if (gen == CommandFlavor.AsyncCommand)
            {
                Write($"self.tpm.dispatch_command({cmdCode}, &req)?;");
            } else if (gen == CommandFlavor.AsyncResponse) {
                Write($"self.tpm.process_response({cmdCode}, &mut resp)?;");
            } else {
                Write($"self.dispatch({cmdCode}, req, &mut resp)?;");
            }

            if (gen == CommandFlavor.AsyncCommand) {
                Write("Ok(())");
            } else {
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
        }

        void GenEnumMap()
        {
            TabIn("lazy_static::lazy_static! {");
            Write("/// Maps enum type IDs to a map of values to string representations");
            Write("static ref ENUM_TO_STR_MAP: HashMap<std::any::TypeId, HashMap<u64, &'static str>> = {");
            TabIn("let mut map = HashMap::new();");
            
            foreach (var e in EnumMap)
            {
                var mutable = e.Value.Count > 0 ? "mut" : "";
                Write($"let {mutable} {ToSnakeCase(e.Key)}_map: HashMap<u64, &'static str> = HashMap::new();");
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
            Write("static ref STR_TO_ENUM_MAP: HashMap<std::any::TypeId, HashMap<&'static str, u64>> = {");
            TabIn("let mut map = HashMap::new();");
            
            foreach (var e in EnumMap)
            {
                var mutable = e.Value.Count > 0 ? "mut" : "";
                Write($"let {mutable} {ToSnakeCase(e.Key)}_map: HashMap<&'static str, u64> = HashMap::new();");
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
        static long ToRustEnumValue(TpmNamedConstant element, int bits, bool signed)
        {
            // If no numeric value was caluclated, return the original value
            // if (element.NumericValue == null)
            // {
            //     return element.Value;
            // }

            return Convert.ToInt64(CastToNumberWithBitsAndSign(element.NumericValue, bits, signed));
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

        private static object CastToNumberWithBitsAndSign(long number, int bits, bool sign)
        {
            if (sign)
            {
                // Cast to signed types
                if (bits == 8)
                {
                    return (sbyte)number;  // Cast to signed byte (8 bits)
                }
                else if (bits == 16)
                {
                    return (short)number;  // Cast to short (16 bits)
                }
                else if (bits == 32)
                {
                    return (int)number;  // Cast to int (32 bits)
                }
                else if (bits == 64)
                {
                    return (long)number;  // Cast to long (64 bits)
                }
            }
            else
            {
                // Cast to unsigned types
                if (bits == 8)
                {
                    return (byte)number;  // Cast to unsigned byte (8 bits)
                }
                else if (bits == 16)
                {
                    return (ushort)number;  // Cast to unsigned short (16 bits)
                }
                else if (bits == 32)
                {
                    return (uint)number;  // Cast to unsigned int (32 bits)
                }
                else if (bits == 64)
                {
                    return (ulong)number;  // Cast to unsigned long (64 bits)
                }
            }
            
            throw new ArgumentException("Unsupported bit size or invalid number range");
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
