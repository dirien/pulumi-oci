// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetNetworkSecurityGroupSecurityRulesSecurityRuleTcpOptionsResult
    {
        public readonly Outputs.GetNetworkSecurityGroupSecurityRulesSecurityRuleTcpOptionsDestinationPortRangeResult DestinationPortRange;
        public readonly Outputs.GetNetworkSecurityGroupSecurityRulesSecurityRuleTcpOptionsSourcePortRangeResult SourcePortRange;

        [OutputConstructor]
        private GetNetworkSecurityGroupSecurityRulesSecurityRuleTcpOptionsResult(
            Outputs.GetNetworkSecurityGroupSecurityRulesSecurityRuleTcpOptionsDestinationPortRangeResult destinationPortRange,

            Outputs.GetNetworkSecurityGroupSecurityRulesSecurityRuleTcpOptionsSourcePortRangeResult sourcePortRange)
        {
            DestinationPortRange = destinationPortRange;
            SourcePortRange = sourcePortRange;
        }
    }
}