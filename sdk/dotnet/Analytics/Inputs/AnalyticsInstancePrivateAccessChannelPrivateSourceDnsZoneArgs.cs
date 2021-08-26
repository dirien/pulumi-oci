// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Analytics.Inputs
{

    public sealed class AnalyticsInstancePrivateAccessChannelPrivateSourceDnsZoneArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Description of private source dns zone.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Private Source DNS Zone. Ex: example-vcn.oraclevcn.com, corp.example.com.
        /// </summary>
        [Input("dnsZone", required: true)]
        public Input<string> DnsZone { get; set; } = null!;

        public AnalyticsInstancePrivateAccessChannelPrivateSourceDnsZoneArgs()
        {
        }
    }
}
