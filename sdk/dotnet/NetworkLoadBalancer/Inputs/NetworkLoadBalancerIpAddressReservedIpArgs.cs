// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer.Inputs
{

    public sealed class NetworkLoadBalancerIpAddressReservedIpArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// OCID of the reserved public IP address created with the virtual cloud network.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        public NetworkLoadBalancerIpAddressReservedIpArgs()
        {
        }
    }
}
