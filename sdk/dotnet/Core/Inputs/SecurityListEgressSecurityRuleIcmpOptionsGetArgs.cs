// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class SecurityListEgressSecurityRuleIcmpOptionsGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The ICMP code (optional).
        /// </summary>
        [Input("code")]
        public Input<int>? Code { get; set; }

        /// <summary>
        /// (Updatable) The ICMP type.
        /// </summary>
        [Input("type", required: true)]
        public Input<int> Type { get; set; } = null!;

        public SecurityListEgressSecurityRuleIcmpOptionsGetArgs()
        {
        }
    }
}
