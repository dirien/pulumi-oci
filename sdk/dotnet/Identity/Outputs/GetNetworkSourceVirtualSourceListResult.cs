// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetNetworkSourceVirtualSourceListResult
    {
        public readonly ImmutableArray<string> IpRanges;
        public readonly string VcnId;

        [OutputConstructor]
        private GetNetworkSourceVirtualSourceListResult(
            ImmutableArray<string> ipRanges,

            string vcnId)
        {
            IpRanges = ipRanges;
            VcnId = vcnId;
        }
    }
}
