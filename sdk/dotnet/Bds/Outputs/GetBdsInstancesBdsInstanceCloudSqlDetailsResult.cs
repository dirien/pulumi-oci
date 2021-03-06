// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Bds.Outputs
{

    [OutputType]
    public sealed class GetBdsInstancesBdsInstanceCloudSqlDetailsResult
    {
        /// <summary>
        /// The size of block volume in GB that needs to be attached to a given node. All the necessary details needed for attachment are managed by service itself.
        /// </summary>
        public readonly string BlockVolumeSizeInGbs;
        /// <summary>
        /// IP address of the node.
        /// </summary>
        public readonly string IpAddress;
        /// <summary>
        /// Boolean flag specifying whether or not Kerberos principals are mapped to database users.
        /// </summary>
        public readonly bool IsKerberosMappedToDatabaseUsers;
        /// <summary>
        /// Details about the Kerberos principals.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBdsInstancesBdsInstanceCloudSqlDetailsKerberosDetailResult> KerberosDetails;
        /// <summary>
        /// Shape of the node.
        /// </summary>
        public readonly string Shape;

        [OutputConstructor]
        private GetBdsInstancesBdsInstanceCloudSqlDetailsResult(
            string blockVolumeSizeInGbs,

            string ipAddress,

            bool isKerberosMappedToDatabaseUsers,

            ImmutableArray<Outputs.GetBdsInstancesBdsInstanceCloudSqlDetailsKerberosDetailResult> kerberosDetails,

            string shape)
        {
            BlockVolumeSizeInGbs = blockVolumeSizeInGbs;
            IpAddress = ipAddress;
            IsKerberosMappedToDatabaseUsers = isKerberosMappedToDatabaseUsers;
            KerberosDetails = kerberosDetails;
            Shape = shape;
        }
    }
}
