// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Inputs
{

    public sealed class GetTargetsFilterArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// configuration name
        /// </summary>
        [Input("name", required: true)]
        public string Name { get; set; } = null!;

        [Input("regex")]
        public bool? Regex { get; set; }

        [Input("values", required: true)]
        private List<string>? _values;

        /// <summary>
        /// List of configuration values
        /// </summary>
        public List<string> Values
        {
            get => _values ?? (_values = new List<string>());
            set => _values = value;
        }

        public GetTargetsFilterArgs()
        {
        }
    }
}
