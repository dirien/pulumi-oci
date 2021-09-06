// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns.Outputs
{

    [OutputType]
    public sealed class GetResolversResolverRuleResult
    {
        public readonly string Action;
        public readonly ImmutableArray<string> ClientAddressConditions;
        public readonly ImmutableArray<string> DestinationAddresses;
        public readonly ImmutableArray<string> QnameCoverConditions;
        public readonly string SourceEndpointName;

        [OutputConstructor]
        private GetResolversResolverRuleResult(
            string action,

            ImmutableArray<string> clientAddressConditions,

            ImmutableArray<string> destinationAddresses,

            ImmutableArray<string> qnameCoverConditions,

            string sourceEndpointName)
        {
            Action = action;
            ClientAddressConditions = clientAddressConditions;
            DestinationAddresses = destinationAddresses;
            QnameCoverConditions = qnameCoverConditions;
            SourceEndpointName = sourceEndpointName;
        }
    }
}
