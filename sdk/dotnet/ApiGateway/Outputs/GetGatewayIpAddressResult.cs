// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Outputs
{

    [OutputType]
    public sealed class GetGatewayIpAddressResult
    {
        /// <summary>
        /// An IP address.
        /// </summary>
        public readonly string IpAddress;

        [OutputConstructor]
        private GetGatewayIpAddressResult(string ipAddress)
        {
            IpAddress = ipAddress;
        }
    }
}