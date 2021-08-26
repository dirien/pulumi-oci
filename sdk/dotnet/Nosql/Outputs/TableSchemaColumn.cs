// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Nosql.Outputs
{

    [OutputType]
    public sealed class TableSchemaColumn
    {
        /// <summary>
        /// The column default value.
        /// </summary>
        public readonly string? DefaultValue;
        /// <summary>
        /// The column nullable flag.
        /// </summary>
        public readonly bool? IsNullable;
        /// <summary>
        /// Table name.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The column type.
        /// </summary>
        public readonly string? Type;

        [OutputConstructor]
        private TableSchemaColumn(
            string? defaultValue,

            bool? isNullable,

            string? name,

            string? type)
        {
            DefaultValue = defaultValue;
            IsNullable = isNullable;
            Name = name;
            Type = type;
        }
    }
}
