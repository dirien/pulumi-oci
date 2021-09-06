// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetTargetDatabasesTargetDatabaseDatabaseDetailsResult
    {
        /// <summary>
        /// The OCID of the autonomous database registered as a target database in Data Safe.
        /// </summary>
        public readonly string AutonomousDatabaseId;
        /// <summary>
        /// A filter to return target databases that match the database type of the target database.
        /// </summary>
        public readonly string DatabaseType;
        /// <summary>
        /// The OCID of the cloud database system registered as a target database in Data Safe.
        /// </summary>
        public readonly string DbSystemId;
        /// <summary>
        /// A filter to return target databases that match the infrastructure type of the target database.
        /// </summary>
        public readonly string InfrastructureType;
        /// <summary>
        /// The OCID of the compute instance on which the database is running.
        /// </summary>
        public readonly string InstanceId;
        /// <summary>
        /// A List of either the IP Addresses or FQDN names of the database hosts.
        /// </summary>
        public readonly ImmutableArray<string> IpAddresses;
        /// <summary>
        /// The port number of the database listener.
        /// </summary>
        public readonly int ListenerPort;
        /// <summary>
        /// The service name of the database registered as target database.
        /// </summary>
        public readonly string ServiceName;
        /// <summary>
        /// The OCID of the VM cluster in which the database is running.
        /// </summary>
        public readonly string VmClusterId;

        [OutputConstructor]
        private GetTargetDatabasesTargetDatabaseDatabaseDetailsResult(
            string autonomousDatabaseId,

            string databaseType,

            string dbSystemId,

            string infrastructureType,

            string instanceId,

            ImmutableArray<string> ipAddresses,

            int listenerPort,

            string serviceName,

            string vmClusterId)
        {
            AutonomousDatabaseId = autonomousDatabaseId;
            DatabaseType = databaseType;
            DbSystemId = dbSystemId;
            InfrastructureType = infrastructureType;
            InstanceId = instanceId;
            IpAddresses = ipAddresses;
            ListenerPort = listenerPort;
            ServiceName = serviceName;
            VmClusterId = vmClusterId;
        }
    }
}
