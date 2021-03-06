// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class WaasPolicyPolicyConfigHealthChecksArgs : Pulumi.ResourceArgs
    {
        [Input("expectedResponseCodeGroups")]
        private InputList<string>? _expectedResponseCodeGroups;

        /// <summary>
        /// (Updatable) The HTTP response codes that signify a healthy state.
        /// * **2XX:** Success response code group.
        /// * **3XX:** Redirection response code group.
        /// * **4XX:** Client errors response code group.
        /// * **5XX:** Server errors response code group.
        /// </summary>
        public InputList<string> ExpectedResponseCodeGroups
        {
            get => _expectedResponseCodeGroups ?? (_expectedResponseCodeGroups = new InputList<string>());
            set => _expectedResponseCodeGroups = value;
        }

        /// <summary>
        /// (Updatable) Health check will search for the given text in a case-sensitive manner within the response body and will fail if the text is not found.
        /// </summary>
        [Input("expectedResponseText")]
        public Input<string>? ExpectedResponseText { get; set; }

        [Input("headers")]
        private InputMap<object>? _headers;

        /// <summary>
        /// (Updatable) HTTP header fields to include in health check requests, expressed as `"name": "value"` properties. Because HTTP header field names are case-insensitive, any use of names that are case-insensitive equal to other names will be rejected. If Host is not specified, requests will include a Host header field with value matching the policy's protected domain. If User-Agent is not specified, requests will include a User-Agent header field with value "waf health checks".
        /// </summary>
        public InputMap<object> Headers
        {
            get => _headers ?? (_headers = new InputMap<object>());
            set => _headers = value;
        }

        /// <summary>
        /// (Updatable) Number of successful health checks after which the server is marked up.
        /// </summary>
        [Input("healthyThreshold")]
        public Input<int>? HealthyThreshold { get; set; }

        /// <summary>
        /// (Updatable) Time between health checks of an individual origin server, in seconds.
        /// </summary>
        [Input("intervalInSeconds")]
        public Input<int>? IntervalInSeconds { get; set; }

        /// <summary>
        /// (Updatable) Enables or disables the JavaScript challenge Web Application Firewall feature.
        /// </summary>
        [Input("isEnabled")]
        public Input<bool>? IsEnabled { get; set; }

        /// <summary>
        /// (Updatable) Enables or disables additional check for predefined text in addition to response code.
        /// </summary>
        [Input("isResponseTextCheckEnabled")]
        public Input<bool>? IsResponseTextCheckEnabled { get; set; }

        /// <summary>
        /// (Updatable) Load balancing methods are algorithms used to efficiently distribute traffic among origin servers.
        /// * **[IP_HASH](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/IPHashLoadBalancingMethod):** All the incoming requests from the same client IP address should go to the same content origination server. IP_HASH load balancing method uses origin weights when choosing which origin should the hash be assigned to initially.
        /// * **[ROUND_ROBIN](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/RoundRobinLoadBalancingMethod):** Forwards requests sequentially to the available origin servers. The first request - to the first origin server, the second request - to the next origin server, and so on. After it sends a request to the last origin server, it starts again with the first origin server. When using weights on origins, Weighted Round Robin assigns more requests to origins with a greater weight. Over a period of time, origins will receive a number of requests in proportion to their weight.
        /// * **[STICKY_COOKIE](https://www.terraform.io/iaas/api/#/en/waas/latest/datatypes/StickyCookieLoadBalancingMethod):** Adds a session cookie to the first response from the origin server and identifies the server that sent the response. The client's next request contains the cookie value, and nginx routes the request to the origin server that responded to the first request. STICKY_COOKIE load balancing method falls back to Round Robin for the first request.
        /// </summary>
        [Input("method")]
        public Input<string>? Method { get; set; }

        /// <summary>
        /// (Updatable) Path to visit on your origins when performing the health check.
        /// </summary>
        [Input("path")]
        public Input<string>? Path { get; set; }

        /// <summary>
        /// (Updatable) Response timeout represents wait time until request is considered failed, in seconds.
        /// </summary>
        [Input("timeoutInSeconds")]
        public Input<int>? TimeoutInSeconds { get; set; }

        /// <summary>
        /// (Updatable) Number of failed health checks after which the server is marked down.
        /// </summary>
        [Input("unhealthyThreshold")]
        public Input<int>? UnhealthyThreshold { get; set; }

        public WaasPolicyPolicyConfigHealthChecksArgs()
        {
        }
    }
}
