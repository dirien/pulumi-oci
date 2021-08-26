// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Outputs
{

    [OutputType]
    public sealed class GetConnectionsConnectionCollectionItemConnectDescriptorResult
    {
        /// <summary>
        /// Connect string.
        /// </summary>
        public readonly string ConnectString;
        /// <summary>
        /// Database service name.
        /// </summary>
        public readonly string DatabaseServiceName;
        /// <summary>
        /// Name of the host the sshkey is valid for.
        /// </summary>
        public readonly string Host;
        /// <summary>
        /// Port of the connect descriptor.
        /// </summary>
        public readonly int Port;

        [OutputConstructor]
        private GetConnectionsConnectionCollectionItemConnectDescriptorResult(
            string connectString,

            string databaseServiceName,

            string host,

            int port)
        {
            ConnectString = connectString;
            DatabaseServiceName = databaseServiceName;
            Host = host;
            Port = port;
        }
    }
}
