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
    public sealed class GetBackendSetsBackendsetBackendResult
    {
        /// <summary>
        /// Whether the load balancer should treat this server as a backup unit. If `true`, the load balancer forwards no ingress traffic to this backend server unless all other backend servers not marked as "backup" fail the health check policy.
        /// </summary>
        public readonly bool Backup;
        /// <summary>
        /// Whether the load balancer should drain this server. Servers marked "drain" receive no new incoming traffic.  Example: `false`
        /// </summary>
        public readonly bool Drain;
        /// <summary>
        /// The IP address of the backend server.  Example: `10.0.0.3`
        /// </summary>
        public readonly string IpAddress;
        /// <summary>
        /// A friendly name for the backend set. It must be unique and it cannot be changed.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Whether the load balancer should treat this server as offline. Offline servers receive no incoming traffic.  Example: `false`
        /// </summary>
        public readonly bool Offline;
        /// <summary>
        /// The backend server port against which to run the health check. If the port is not specified, the load balancer uses the port information from the `Backend` object.  Example: `8080`
        /// </summary>
        public readonly int Port;
        /// <summary>
        /// The load balancing policy weight assigned to the server. Backend servers with a higher weight receive a larger proportion of incoming traffic. For example, a server weighted '3' receives 3 times the number of new connections as a server weighted '1'. For more information on load balancing policies, see [How Load Balancing Policies Work](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/lbpolicies.htm).  Example: `3`
        /// </summary>
        public readonly int Weight;

        [OutputConstructor]
        private GetBackendSetsBackendsetBackendResult(
            bool backup,

            bool drain,

            string ipAddress,

            string name,

            bool offline,

            int port,

            int weight)
        {
            Backup = backup;
            Drain = drain;
            IpAddress = ipAddress;
            Name = name;
            Offline = offline;
            Port = port;
            Weight = weight;
        }
    }
}
