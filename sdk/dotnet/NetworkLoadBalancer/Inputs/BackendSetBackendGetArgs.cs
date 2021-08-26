// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer.Inputs
{

    public sealed class BackendSetBackendGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The IP address of the backend server. Example: `10.0.0.3`
        /// </summary>
        [Input("ipAddress")]
        public Input<string>? IpAddress { get; set; }

        /// <summary>
        /// Whether the network load balancer should treat this server as a backup unit. If `true`, then the network load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as "isBackup" fail the health check policy.  Example: `false`
        /// </summary>
        [Input("isBackup")]
        public Input<bool>? IsBackup { get; set; }

        /// <summary>
        /// Whether the network load balancer should drain this server. Servers marked "isDrain" receive no  incoming traffic.  Example: `false`
        /// </summary>
        [Input("isDrain")]
        public Input<bool>? IsDrain { get; set; }

        /// <summary>
        /// Whether the network load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
        /// </summary>
        [Input("isOffline")]
        public Input<bool>? IsOffline { get; set; }

        /// <summary>
        /// A user-friendly name for the backend set that must be unique and cannot be changed.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) The backend server port against which to run the health check. If the port is not specified, then the network load balancer uses the port information from the `Backend` object. The port must be specified if the backend port is 0.  Example: `8080`
        /// </summary>
        [Input("port", required: true)]
        public Input<int> Port { get; set; } = null!;

        /// <summary>
        /// The IP OCID/Instance OCID associated with the backend server. Example: `ocid1.privateip..oc1.&lt;var&gt;&amp;lt;unique_ID&amp;gt;&lt;/var&gt;`
        /// </summary>
        [Input("targetId")]
        public Input<string>? TargetId { get; set; }

        /// <summary>
        /// The network load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted '3' receives three times the number of new connections as a server weighted '1'. For more information about load balancing policies, see [How Network Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
        /// </summary>
        [Input("weight")]
        public Input<int>? Weight { get; set; }

        public BackendSetBackendGetArgs()
        {
        }
    }
}
