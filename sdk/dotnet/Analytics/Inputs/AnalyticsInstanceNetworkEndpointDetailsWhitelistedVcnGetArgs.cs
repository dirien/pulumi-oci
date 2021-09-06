// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Analytics.Inputs
{

    public sealed class AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The Virtual Cloud Network OCID.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        [Input("whitelistedIps")]
        private InputList<string>? _whitelistedIps;

        /// <summary>
        /// Source IP addresses or IP address ranges igress rules.
        /// </summary>
        public InputList<string> WhitelistedIps
        {
            get => _whitelistedIps ?? (_whitelistedIps = new InputList<string>());
            set => _whitelistedIps = value;
        }

        public AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcnGetArgs()
        {
        }
    }
}
