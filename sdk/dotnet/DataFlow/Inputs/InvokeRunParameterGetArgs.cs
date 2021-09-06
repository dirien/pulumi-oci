// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataFlow.Inputs
{

    public sealed class InvokeRunParameterGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The name of the parameter.  It must be a string of one or more word characters (a-z, A-Z, 0-9, _). Examples: "iterations", "input_file"
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        /// <summary>
        /// The value of the parameter. It must be a string of 0 or more characters of any kind. Examples: "" (empty string), "10", "mydata.xml", "${x}"
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public InvokeRunParameterGetArgs()
        {
        }
    }
}
