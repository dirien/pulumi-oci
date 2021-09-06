// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Outputs
{

    [OutputType]
    public sealed class WaasPolicyPolicyConfigLoadBalancingMethod
    {
        /// <summary>
        /// (Updatable) The domain for which the cookie is set, defaults to WAAS policy domain.
        /// </summary>
        public readonly string? Domain;
        /// <summary>
        /// (Updatable) The time for which a browser should keep the cookie in seconds. Empty value will cause the cookie to expire at the end of a browser session.
        /// </summary>
        public readonly int? ExpirationTimeInSeconds;
        /// <summary>
        /// (Updatable) Load balancing methods are algorithms used to efficiently distribute traffic among origin servers.
        /// * **[IP_HASH](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/IPHashLoadBalancingMethod):** All the incoming requests from the same client IP address should go to the same content origination server. IP_HASH load balancing method uses origin weights when choosing which origin should the hash be assigned to initially.
        /// * **[ROUND_ROBIN](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/RoundRobinLoadBalancingMethod):** Forwards requests sequentially to the available origin servers. The first request - to the first origin server, the second request - to the next origin server, and so on. After it sends a request to the last origin server, it starts again with the first origin server. When using weights on origins, Weighted Round Robin assigns more requests to origins with a greater weight. Over a period of time, origins will receive a number of requests in proportion to their weight.
        /// * **[STICKY_COOKIE](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/StickyCookieLoadBalancingMethod):** Adds a session cookie to the first response from the origin server and identifies the server that sent the response. The client's next request contains the cookie value, and nginx routes the request to the origin server that responded to the first request. STICKY_COOKIE load balancing method falls back to Round Robin for the first request.
        /// </summary>
        public readonly string Method;
        /// <summary>
        /// (Updatable) The unique name of the whitelist.
        /// </summary>
        public readonly string? Name;

        [OutputConstructor]
        private WaasPolicyPolicyConfigLoadBalancingMethod(
            string? domain,

            int? expirationTimeInSeconds,

            string method,

            string? name)
        {
            Domain = domain;
            ExpirationTimeInSeconds = expirationTimeInSeconds;
            Method = method;
            Name = name;
        }
    }
}
