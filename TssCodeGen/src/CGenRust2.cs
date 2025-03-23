// /*
//  *  Copyright (c) Microsoft Corporation. All rights reserved.
//  *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
//  */

// using System.Diagnostics;
// using System.Collections.Generic;
// using System.Linq;

// namespace CodeGen
// {
//     /// <summary> Rust TSS code generator </summary>
//     class CGenRust : CodeGenBase
//     {
//         // Maps enum type to a map of enumerator names to values
//         Dictionary<string, Dictionary<string, string>> EnumMap;

//         public CGenRust(string rootDir) : base(rootDir, @"Src\TpmExtensions.rs.snips") {}

//         internal override void Generate()
//         {
//             EnumMap = new Dictionary<string, Dictionary<string, string>>();

//             GenerateTpmTypesRs();
//             UpdateExistingSource(@"src\tpm_types.rs");

//             GenerateTpmCommandPrototypes();
//             UpdateExistingSource(@"src\tpm2.rs");

//             GenerateTpmTypesImpl();
//             UpdateExistingSource(@"src\tpm_types_impl.rs");
//         }

//         /// <summary> Determines whether this struct is represented as a type alias in Rust </summary>
//         static bool IsTypedefStruct(TpmStruct s)
//         {
//             return s.DerivedFrom != null && s.ContainingUnions.Count == 0;
//         }

//         static string CtorParamTypeFor(StructField f)
//         {
//             if (f.IsArray() || !f.IsValueType())
//                 return $"&{f.TypeName}";
//             return f.TypeName;
//         }

//         static string TransType(StructField f)
//         {
//             if (f.MarshalType == MarshalType.UnionObject)
//                 return $"Option<Box<{f.TypeName}>>";
//             return f.TypeName;
//         }

//         string GetCommandReturnType(CommandFlavor gen, TpmStruct resp, string methodName,
//                                     out string returnFieldName)
//         {
//             returnFieldName = null;
//             if (gen == CommandFlavor.AsyncCommand)
//                 return "Result<(), TpmError>";

//             string returnType = "Result<(), TpmError>";
//             var respFields = resp.NonTagFields;
//             if (ForceJustOneReturnParm.Contains(methodName))
//             {
//                 respFields = respFields.Take(1).ToArray();
//             }

//             if (respFields.Count() > 1)
//                 return $"Result<{resp.Name}, TpmError>";

//             if (respFields.Count() == 1)
//             {
//                 returnFieldName = respFields[0].Name;
//                 returnType = $"Result<{TransType(respFields[0])}, TpmError>";
//             }
//             return returnType;
//         }

//         void GenerateTpmTypesRs()
//         {
//             // Add module documentation
//             Write("//! TPM type definitions for the Rust TSS implementation");
//             Write("");
//             Write("use std::convert::TryFrom;");
//             Write("use std::collections::HashMap;");
//             Write("use crate::error::*;");
//             Write("use crate::tpm_buffer::*;");
//             Write("use crate::serialization::*;");
//             Write("");
            
//             foreach (var e in TpmTypes.Get<TpmEnum>())
//                 GenEnum(e);

//             foreach (var bf in TpmTypes.Get<TpmBitfield>())
//                 GenBitfield(bf);
                
//             WriteComment("Base trait for TPM union interfaces");
//             Write("pub trait TpmUnion {");
//             TabIn("/// Gets the union selector value");
//             Write("fn get_union_selector(&self) -> u32;");
//             TabOut("}");
//             Write("");

//             foreach (var u in TpmTypes.Get<TpmUnion>())
//                 GenUnion(u);

//             foreach (var s in TpmTypes.Get<TpmStruct>())
//                 GenStructDecl(s);
//         }

//         void GenEnum(TpmType e, List<TpmNamedConstant> elements)
//         {
//             WriteComment(e);
//             Write($"#[derive(Debug, Clone, Copy, PartialEq, Eq)]");
//             Write($"#[repr(u{e.GetFinalUnderlyingType().GetSize() * 8})]");
//             Write($"pub enum {e.Name} {{");
//             TabIn();

//             var enumVals = new Dictionary<string, string>();
//             foreach (var elt in elements)
//             {
//                 WriteComment(AsSummary(elt.Comment));
//                 Write($"{elt.Name} = {elt.Value},");

//                 // Do not include artificially added named constants into the name conversion maps
//                 if (elt.SpecName != null)
//                     enumVals[elt.Name] = e is TpmEnum ? ToHex(elt.NumericValue) : elt.Value;
//             }
//             TabOut("}");
//             Write("");
            
//             // Add implementations for the enum
//             Write($"impl TryFrom<u{e.GetFinalUnderlyingType().GetSize() * 8}> for {e.Name} {{");
//             TabIn("type Error = TpmError;");
//             Write("");
//             Write($"fn try_from(value: u{e.GetFinalUnderlyingType().GetSize() * 8}) -> Result<Self, Self::Error> {{");
//             TabIn("match value {");
//             foreach (var elt in elements)
//             {
//                 Write($"{elt.Value} => Ok(Self::{elt.Name}),");
//             }
//             Write($"_ => Err(TpmError::InvalidEnumValue),");
//             TabOut("}");
//             TabOut("}");
//             TabOut("}");
//             Write("");
            
//             EnumMap[e.Name] = enumVals;
//         }

//         void GenEnum(TpmEnum e)
//         {
//             GenEnum(e, e.Members);
//         }

//         void GenBitfield(TpmBitfield bf)
//         {
//             GenEnum(bf, GetBifieldElements(bf));
//         }

//         void GenUnion(TpmUnion u)
//         {
//             if (!u.Implement)
//                 return;

//             WriteComment(u);
//             Write($"pub enum {u.Name} {{");
//             TabIn();
            
//             foreach (var member in u.Members)
//             {
//                 if (member.Type.IsElementary())
//                 {
//                     Write($"{member.Name},");
//                 }
//                 else
//                 {
//                     Write($"{member.Name}({member.Type.Name}),");
//                 }
//             }
            
//             TabOut("}");
//             Write("");
            
//             // Implement TpmUnion trait
//             Write($"impl TpmUnion for {u.Name} {{");
//             TabIn("fn get_union_selector(&self) -> u32 {");
//             TabIn("match self {");
//             foreach (var member in u.Members)
//             {
//                 if (member.Type.IsElementary())
//                 {
//                     Write($"Self::{member.Name} => {member.SelectorValue.QualifiedName} as u32,");
//                 }
//                 else
//                 {
//                     Write($"Self::{member.Name}(_) => {member.SelectorValue.QualifiedName} as u32,");
//                 }
//             }
//             TabOut("}");
//             TabOut("}");
//             TabOut("}");
//             Write("");
//         }

//         string GetUnionSelectorType(TpmUnion u)
//         {
//             // Take the type from the first member's selector value
//             var firstMember = u.Members.First();
//             return firstMember.SelectorValue.Name.Split('.')[0];
//         }

//         string GetUnionMemberSelectorInfo(TpmStruct s, out string selVal)
//         {
//             selVal = null;
//             if (s.ContainingUnions.Count == 0)
//                 return null;

//             // Find the containing union and the corresponding member
//             var union = s.ContainingUnions[0];
//             var member = union.Members.First(m => m.Type == s);
//             if (member == null)
//                 return null;

//             selVal = $"{union.Name}::{member.SelectorValue.Name}";
//             return GetUnionSelectorType(union);
//         }

//         void GenGetUnionSelector(TpmStruct s)
//         {
//             string selType = GetUnionMemberSelectorInfo(s, out string selVal);
//             if (selType != null)
//             {
//                 WriteComment("TpmUnion trait implementation");
//                 Write("fn get_union_selector(&self) -> u32 {");
//                 TabIn($"return {selVal} as u32;");
//                 TabOut("}");
//             }
//         }

//         void GenStructDecl(TpmStruct s)
//         {
//             string structName = s.Name;

//             if (IsTypedefStruct(s))
//             {
//                 Debug.Assert(s.Fields.Count == 0);
//                 WriteComment(s);
//                 Write($"pub type {structName} = {s.DerivedFrom.Name};");
//                 Write("");
//                 return;
//             }

//             WriteComment(s);
//             Write("#[derive(Debug, Clone)]");
//             Write($"pub struct {structName} {{");
//             TabIn();

//             // Fields
//             foreach (var f in s.NonSizeFields)
//             {
//                 if (f.MarshalType == MarshalType.ConstantValue)
//                     // No member field for a constant tag
//                     continue;

//                 WriteComment(f);
//                 if (f.MarshalType == MarshalType.UnionSelector)
//                 {
//                     // In Rust, we'll make this a method rather than a field
//                     continue;
//                 }

//                 Write($"pub {ToSnakeCase(f.Name)}: {TransType(f)},");
//             }

//             TabOut("}");
//             Write("");

//             // Default implementation
//             Write($"impl Default for {structName} {{");
//             TabIn("fn default() -> Self {");
//             TabIn("Self {");
            
//             foreach (var f in s.NonSizeFields)
//             {
//                 if (f.MarshalType == MarshalType.ConstantValue)
//                     continue;
//                 if (f.MarshalType == MarshalType.UnionSelector)
//                     continue;
                    
//                 string defaultValue = GetRustDefaultValue(f);
//                 Write($"{ToSnakeCase(f.Name)}: {defaultValue},");
//             }
            
//             TabOut("}");
//             TabOut("}");
//             TabOut("}");
//             Write("");

//             // Implementation block
//             Write($"impl {structName} {{");
//             TabIn();
            
//             // Constructor
//             if (!s.Info.IsResponse() && s.NonTagFields.Count() != 0)
//             {
//                 Write($"pub fn new(");
//                 TabIn();
                
//                 bool first = true;
//                 foreach (var f in s.NonTagFields)
//                 {
//                     if (!first) Write(",");
//                     first = false;
//                     Write($"{ToSnakeCase(f.Name)}: {TransType(f)}");
//                 }
                
//                 TabOut($") -> Self {{");
//                 TabIn("Self {");
                
//                 foreach (var f in s.NonTagFields)
//                 {
//                     Write($"{ToSnakeCase(f.Name)},");
//                 }
                
//                 TabOut("}");
//                 TabOut("}");
//             }
            
//             // Union selector method if needed
//             if (s.Fields.Any(f => f.MarshalType == MarshalType.UnionSelector))
//             {
//                 foreach (var f in s.Fields.Where(f => f.MarshalType == MarshalType.UnionSelector))
//                 {
//                     var unionField = f.RelatedUnion;
//                     var u = (TpmUnion)unionField.Type;
                    
//                     Write($"pub fn {ToSnakeCase(f.Name)}(&self) -> {f.TypeName} {{");
//                     TabIn();
                    
//                     if (u.NullSelector == null)
//                     {
//                         Write($"self.{ToSnakeCase(unionField.Name)}.as_ref().map_or(0, |u| u.get_union_selector() as {f.TypeName})");
//                     }
//                     else
//                     {
//                         Write($"self.{ToSnakeCase(unionField.Name)}.as_ref().map_or({u.NullSelector.QualifiedName}, |u| u.get_union_selector() as {f.TypeName})");
//                     }
                    
//                     TabOut("}");
//                 }
//             }

//             // Union implementation
//             GenGetUnionSelector(s);
            
//             // Marshaling methods
//             Write("pub fn to_tpm(&self, buf: &mut TpmBuffer) -> Result<(), TpmError> {");
//             TabIn("// Implement marshaling to TPM");
//             Write("Ok(())");
//             TabOut("}");
            
//             Write("");
//             Write("pub fn from_tpm(buf: &mut TpmBuffer) -> Result<Self, TpmError> {");
//             TabIn("// Implement unmarshaling from TPM");
//             Write("Ok(Self::default())");
//             TabOut("}");
            
//             TabOut("}");
//             Write("");
//         }

//         string ToSnakeCase(string name)
//         {
//             // Convert camelCase or PascalCase to snake_case
//             if (string.IsNullOrEmpty(name))
//                 return name;
                
//             return char.ToLowerInvariant(name[0]) + 
//                    string.Concat(name.Skip(1).Select(c => char.IsUpper(c) ? "_" + char.ToLowerInvariant(c) : c.ToString()));
//         }
        
//         string GetRustDefaultValue(StructField f)
//         {
//             if (f.HasInitVal())
//                 return ConvertInitValToRust(f.GetInitVal());
                
//             if (f.MarshalType == MarshalType.UnionObject)
//                 return "None";
                
//             if (f.Type.IsElementary())
//             {
//                 switch (f.TypeName)
//                 {
//                     case "u8":
//                     case "u16":
//                     case "u32": 
//                     case "u64": return "0";
//                     case "bool": return "false";
//                     default: return "Default::default()";
//                 }
//             }
                
//             if (f.IsArray())
//                 return "Vec::new()";
                
//             return "Default::default()";
//         }
        
//         string ConvertInitValToRust(string cppInitVal)
//         {
//             // Simple conversion, would need to be enhanced for real implementation
//             return cppInitVal;
//         }

//         void GenerateTpmCommandPrototypes()
//         {
//             // Module documentation
//             Write("//! TPM2 command implementations");
//             Write("");
//             Write("use crate::error::*;");
//             Write("use crate::tpm_buffer::*;");
//             Write("use crate::tpm_types::*;");
//             Write("");
            
//             // Command prototypes
//             var commands = TpmTypes.Get<TpmStruct>().Where(s => s.Info.IsRequest());

//             Write("pub struct Tpm2 {");
//             TabIn("// Implementation details");
//             TabOut("}");
//             Write("");
            
//             Write("impl Tpm2 {");
//             TabIn();

//             foreach (TpmStruct s in commands)
//                 GenCommand(s, CommandFlavor.Synch);
                
//             TabOut("}");
//             Write("");
            
//             Write("pub struct AsyncMethods<'a> {");
//             TabIn("the_tpm: &'a mut Tpm2,");
//             TabOut("}");
//             Write("");
            
//             Write("impl<'a> AsyncMethods<'a> {");
//             TabIn();
            
//             foreach (TpmStruct s in commands)
//                 GenCommand(s, CommandFlavor.AsyncCommand);
                
//             foreach (TpmStruct s in commands)
//                 GenCommand(s, CommandFlavor.AsyncResponse);
                
//             TabOut("}");
//             Write("");
            
//             Write("impl Tpm2 {");
//             TabIn("pub fn async_methods(&mut self) -> AsyncMethods {");
//             TabIn("AsyncMethods {");
//             Write("the_tpm: self,");
//             TabOut("}");
//             TabOut("}");
//             TabOut("}");
//         }

//         enum CommandFlavor
//         {
//             Synch, AsyncCommand, AsyncResponse
//         }

//         void GenCommand(TpmStruct req, CommandFlavor gen)
//         {
//             var resp = GetRespStruct(req);
//             string cmdName = ToSnakeCase(GetCommandName(req));
//             if (gen == CommandFlavor.AsyncResponse)
//                 cmdName += "_complete";
                
//             string annotation = Helpers.WrapText(AsSummary(req.Comment)) + eol;
//             var reqFields = new StructField[0];
//             if (gen != CommandFlavor.AsyncResponse)
//             {
//                 reqFields = req.NonTagFields;
//                 foreach (var f in reqFields)
//                     annotation += GetParamComment(f) + eol;
//             }
//             WriteComment(annotation + (GetReturnComment(resp.NonTagFields)), false);

//             string returnType = GetCommandReturnType(gen, resp, cmdName, out string returnFieldName);
            
//             Write("pub fn " + cmdName + "(");
//             TabIn();
            
//             Write("&mut self,");
            
//             if (gen != CommandFlavor.AsyncResponse && reqFields.Length > 0)
//             {
//                 foreach (var f in reqFields)
//                 {
//                     Write($"{ToSnakeCase(f.Name)}: {TransType(f)},");
//                 }
//             }
            
//             TabOut($") -> {returnType} {{");
//             TabIn("// Implementation");
//             Write("unimplemented!()");
//             TabOut("}");
//             Write("");
//         }

//         void GenerateTpmTypesImpl()
//         {
//             // Module documentation
//             Write("//! TPM type implementations");
//             Write("");
//             Write("use crate::error::*;");
//             Write("use crate::tpm_buffer::*;");
//             Write("use crate::tpm_types::*;");
//             Write("");
            
//             GenEnumMap();
//             GenUnionFactory();
//             GenStructsImpl();
//             GenCommandDispatchers();
//         }

//         void GenEnumMap()
//         {
//             Write("lazy_static::lazy_static! {");
//             TabIn("static ref ENUM_TO_STR_MAP: HashMap<std::any::TypeId, HashMap<u32, &'static str>> = {");
//             TabIn("let mut map = HashMap::new();");
            
//             foreach (var e in EnumMap)
//             {
//                 Write($"let mut {ToSnakeCase(e.Key)}_map = HashMap::new();");
//                 foreach (var v in e.Value)
//                 {
//                     Write($"{ToSnakeCase(e.Key)}_map.insert({v.Value}, \"{v.Key}\");");
//                 }
//                 Write($"map.insert(std::any::TypeId::of::<{e.Key}>(), {ToSnakeCase(e.Key)}_map);");
//                 Write("");
//             }
            
//             Write("map");
//             TabOut("};");
            
//             Write("");
            
//             Write("static ref STR_TO_ENUM_MAP: HashMap<std::any::TypeId, HashMap<&'static str, u32>> = {");
//             TabIn("let mut map = HashMap::new();");
            
//             foreach (var e in EnumMap)
//             {
//                 Write($"let mut {ToSnakeCase(e.Key)}_map = HashMap::new();");
//                 foreach (var v in e.Value)
//                 {
//                     Write($"{ToSnakeCase(e.Key)}_map.insert(\"{v.Key}\", {v.Value});");
//                 }
//                 Write($"map.insert(std::any::TypeId::of::<{e.Key}>(), {ToSnakeCase(e.Key)}_map);");
//                 Write("");
//             }
            
//             Write("map");
//             TabOut("};");
//             TabOut("}");
//             Write("");
//         }

//         void GenUnionFactory()
//         {
//             var unions = TpmTypes.Get<TpmUnion>();

//             WriteComment("Union factory for creating union instances from selector values");
//             Write("pub struct UnionFactory;");
//             Write("");
//             Write("impl UnionFactory {");
//             TabIn("pub fn create<T: TpmUnion>(selector: u32) -> Option<Box<T>> {");
//             TabIn("let type_id = std::any::TypeId::of::<T>();");
//             Write("");
            
//             string ifPrefix = "if";
//             foreach (TpmUnion u in unions)
//             {
//                 Write($"{ifPrefix} type_id == std::any::TypeId::of::<{u.Name}>() {{");
//                 TabIn("match selector {");
                
//                 foreach (UnionMember m in u.Members)
//                 {
//                     if (m.Type.IsElementary())
//                     {
//                         Write($"{m.SelectorValue.QualifiedName} => Some(Box::new({u.Name}::{m.Name}) as Box<T>),");
//                     }
//                     else
//                     {
//                         Write($"{m.SelectorValue.QualifiedName} => Some(Box::new({u.Name}::{m.Name}({m.Type.Name}::default())) as Box<T>),");
//                     }
//                 }
                
//                 Write("_ => None,");
//                 TabOut("}");
//                 TabOut("}");
                
//                 ifPrefix = "else if";
//             }
            
//             Write("else {");
//             TabIn("None");
//             TabOut("}");
            
//             TabOut("}");
//             TabOut("}");
//             Write("");
//         }

//         void GenStructsImpl()
//         {
//             foreach (var s in TpmTypes.Get<TpmStruct>())
//             {
//                 if (IsTypedefStruct(s))
//                     continue;
                    
//                 GenStructMarshalingImpl(s);
//             }
//         }

//         void GenStructMarshalingImpl(TpmStruct s)
//         {
//             Write($"impl {s.Name} {{");
//             TabIn("// Implement full marshaling/unmarshaling methods");
//             TabOut("}");
//             Write("");
//         }

//         void GenCommandDispatchers()
//         {
//             var cmdRequestStructs = TpmTypes.Get<TpmStruct>().Where(s => s.Info.IsRequest());

//             Write("impl Tpm2 {");
//             TabIn();
            
//             foreach (var s in cmdRequestStructs)
//                 GenCommandDispatcher(s, CommandFlavor.Synch);
                
//             TabOut("}");
//             Write("");
            
//             Write("impl<'a> AsyncMethods<'a> {");
//             TabIn();
            
//             foreach (var s in cmdRequestStructs)
//                 GenCommandDispatcher(s, CommandFlavor.AsyncCommand);
                
//             foreach (var s in cmdRequestStructs)
//                 GenCommandDispatcher(s, CommandFlavor.AsyncResponse);
                
//             TabOut("}");
//         }

//         void GenCommandDispatcher(TpmStruct req, CommandFlavor gen)
//         {
//             var resp = GetRespStruct(req);
//             string cmdName = ToSnakeCase(GetCommandName(req));
//             string cmdCode = $"TPM_CC::{GetCommandName(req)}";

//             if (gen == CommandFlavor.AsyncCommand) { /* Nothing to add */ }
//             else if (gen == CommandFlavor.AsyncResponse) cmdName += "_complete";

//             string returnFieldName;
//             string returnType = GetCommandReturnType(gen, resp, cmdName, out returnFieldName);

//             Write($"fn {cmdName}_dispatcher(");
//             TabIn();
            
//             Write("&mut self,");
            
//             bool paramsPresent = gen != CommandFlavor.AsyncResponse;
//             var cmdParamFields = paramsPresent ? req.NonTagFields : new StructField[0];
            
//             if (paramsPresent && cmdParamFields.Length > 0)
//             {
//                 foreach (var f in cmdParamFields)
//                 {
//                     Write($"{ToSnakeCase(f.Name)}: {TransType(f)},");
//                 }
//             }
            
//             TabOut($") -> {returnType} {{");
//             TabIn("// Implementation");
//             Write("unimplemented!()");
//             TabOut("}");
//             Write("");
//         }

//         protected override void WriteComment(string comment, bool wrap = true)
//         {
//             WriteComment(comment, "/// ", "/// ", "", wrap);
//         }
//     }
// }
