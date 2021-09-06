// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Inputs
{

    public sealed class BackendSetBackendGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as "backup" fail the health check policy.
        /// </summary>
        [Input("backup")]
        public Input<bool>? Backup { get; set; }

        /// <summary>
        /// Whether the load balancer should drain this server. Servers marked "drain" receive no new incoming traffic.  Example: `false`
        /// </summary>
        [Input("drain")]
        public Input<bool>? Drain { get; set; }

        /// <summary>
        /// The IP address of the backend server.  Example: `10.0.0.3`
        /// </summary>
        [Input("ipAddress", required: true)]
        public Input<string> IpAddress { get; set; } = null!;

        /// <summary>
        /// A friendly name for the backend set. It must be unique and it cannot be changed.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
        /// </summary>
        [Input("offline")]
        public Input<bool>? Offline { get; set; }

        /// <summary>
        /// (Updatable) The backend server port against which to run the health check. If the port is not specified, the load balancer uses the port information from the `Backend` object.  Example: `8080`
        /// </summary>
        [Input("port", required: true)]
        public Input<int> Port { get; set; } = null!;

        /// <summary>
        /// The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted '3' receives 3 times the number of new connections as a server weighted '1'. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
        /// </summary>
        [Input("weight")]
        public Input<int>? Weight { get; set; }

        public BackendSetBackendGetArgs()
        {
        }
    }
}
