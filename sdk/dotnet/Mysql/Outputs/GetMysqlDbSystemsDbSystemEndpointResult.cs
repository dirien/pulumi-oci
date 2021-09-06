// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Outputs
{

    [OutputType]
    public sealed class GetMysqlDbSystemsDbSystemEndpointResult
    {
        /// <summary>
        /// The network address of the DB System.
        /// </summary>
        public readonly string Hostname;
        /// <summary>
        /// The IP address the DB System is configured to listen on. A private IP address of the primary endpoint of the DB System. Must be an available IP address within the subnet's CIDR. This will be a "dotted-quad" style IPv4 address.
        /// </summary>
        public readonly string IpAddress;
        /// <summary>
        /// The access modes from the client that this endpoint supports.
        /// </summary>
        public readonly ImmutableArray<string> Modes;
        /// <summary>
        /// The port for primary endpoint of the DB System to listen on.
        /// </summary>
        public readonly int Port;
        /// <summary>
        /// The network port on which X Plugin listens for TCP/IP connections. This is the X Plugin equivalent of port.
        /// </summary>
        public readonly int PortX;
        /// <summary>
        /// The state of the endpoints, as far as it can seen from the DB System. There may be some inconsistency with the actual state of the MySQL service.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Additional information about the current endpoint status.
        /// </summary>
        public readonly string StatusDetails;

        [OutputConstructor]
        private GetMysqlDbSystemsDbSystemEndpointResult(
            string hostname,

            string ipAddress,

            ImmutableArray<string> modes,

            int port,

            int portX,

            string status,

            string statusDetails)
        {
            Hostname = hostname;
            IpAddress = ipAddress;
            Modes = modes;
            Port = port;
            PortX = portX;
            Status = status;
            StatusDetails = statusDetails;
        }
    }
}
