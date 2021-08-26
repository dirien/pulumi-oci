// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class WaasPolicyWafConfigJsChallengeSetHttpHeaderArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The unique name of the whitelist.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        /// <summary>
        /// (Updatable) The value of the header.
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public WaasPolicyWafConfigJsChallengeSetHttpHeaderArgs()
        {
        }
    }
}
