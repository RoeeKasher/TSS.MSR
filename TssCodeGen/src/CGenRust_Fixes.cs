/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Collections.Generic;
using System.Linq;

namespace CodeGen
{
    /// <summary>
    /// Contains extension methods and helper functions to fix issues in CGenRust.cs
    /// </summary>
    public static class CGenRustFixes
    {
        /// <summary>
        /// Gets the response fields for a command struct - to be used in CGenRust.cs
        /// </summary>
        /// <param name="s">The command struct</param>
        /// <returns>The list of response fields</returns>
        public static List<StructField> GetResponseFields(TpmStruct s)
        {
            // If this is a command struct, find its corresponding response struct
            if (s.IsCmdStruct())
            {
                string respName = s.SpecName.Replace("_Command", "_Response");
                if (TpmTypes.Contains(respName))
                {
                    TpmStruct respStruct = (TpmStruct)TpmTypes.Lookup(respName);
                    return respStruct.Fields;
                }
            }
            return new List<StructField>();
        }
    }
}
