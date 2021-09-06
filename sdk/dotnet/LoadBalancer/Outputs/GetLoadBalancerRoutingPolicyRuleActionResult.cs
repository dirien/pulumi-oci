// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Outputs
{

    [OutputType]
    public sealed class GetLoadBalancerRoutingPolicyRuleActionResult
    {
        /// <summary>
        /// Name of the backend set the listener will forward the traffic to.  Example: `backendSetForImages`
        /// </summary>
        public readonly string BackendSetName;
        /// <summary>
        /// A unique name for the routing policy rule. Avoid entering confidential information.
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetLoadBalancerRoutingPolicyRuleActionResult(
            string backendSetName,

            string name)
        {
            BackendSetName = backendSetName;
            Name = name;
        }
    }
}
