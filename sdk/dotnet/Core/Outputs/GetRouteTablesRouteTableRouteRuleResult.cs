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
    public sealed class GetRouteTablesRouteTableRouteRuleResult
    {
        /// <summary>
        /// Deprecated. Instead use `destination` and `destinationType`. Requests that include both `cidrBlock` and `destination` will be rejected.
        /// </summary>
        public readonly string CidrBlock;
        /// <summary>
        /// An optional description of your choice for the rule.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Conceptually, this is the range of IP addresses used for matching when routing traffic. Required if you provide a `destinationType`.
        /// </summary>
        public readonly string Destination;
        /// <summary>
        /// Type of destination for the rule. Required if you provide a `destination`.
        /// * `CIDR_BLOCK`: If the rule's `destination` is an IP address range in CIDR notation.
        /// * `SERVICE_CIDR_BLOCK`: If the rule's `destination` is the `cidrBlock` value for a [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) (the rule is for traffic destined for a particular `Service` through a service gateway).
        /// </summary>
        public readonly string DestinationType;
        /// <summary>
        /// The OCID for the route rule's target. For information about the type of targets you can specify, see [Route Tables](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm).
        /// </summary>
        public readonly string NetworkEntityId;

        [OutputConstructor]
        private GetRouteTablesRouteTableRouteRuleResult(
            string cidrBlock,

            string description,

            string destination,

            string destinationType,

            string networkEntityId)
        {
            CidrBlock = cidrBlock;
            Description = description;
            Destination = destination;
            DestinationType = destinationType;
            NetworkEntityId = networkEntityId;
        }
    }
}
