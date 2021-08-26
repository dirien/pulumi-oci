// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Nosql.Inputs
{

    public sealed class IndexKeyArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The name of a column to be included as an index key.
        /// </summary>
        [Input("columnName", required: true)]
        public Input<string> ColumnName { get; set; } = null!;

        /// <summary>
        /// If the specified column is of type JSON, jsonFieldType contains the type of the field indicated by jsonPath.
        /// </summary>
        [Input("jsonFieldType")]
        public Input<string>? JsonFieldType { get; set; }

        /// <summary>
        /// If the specified column is of type JSON, jsonPath contains a dotted path indicating the field within the JSON object that will be the index key.
        /// </summary>
        [Input("jsonPath")]
        public Input<string>? JsonPath { get; set; }

        public IndexKeyArgs()
        {
        }
    }
}
