// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Outputs
{

    [OutputType]
    public sealed class GetIdentityNetworkSourcesNetworkSourceVirtualSourceListResult
    {
        public readonly ImmutableArray<string> IpRanges;
        public readonly string VcnId;

        [OutputConstructor]
        private GetIdentityNetworkSourcesNetworkSourceVirtualSourceListResult(
            ImmutableArray<string> ipRanges,

            string vcnId)
        {
            IpRanges = ipRanges;
            VcnId = vcnId;
        }
    }
}