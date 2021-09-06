// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetBackupDestinationMountTypeDetailsResult
    {
        /// <summary>
        /// The local directory path on each VM cluster node where the NFS server location is mounted. The local directory path and the NFS server location must each be the same across all of the VM cluster nodes. Ensure that the NFS mount is maintained continuously on all of the VM cluster nodes.
        /// </summary>
        public readonly string LocalMountPointPath;
        public readonly string MountType;
        /// <summary>
        /// Specifies the directory on which to mount the file system
        /// </summary>
        public readonly string NfsServerExport;
        /// <summary>
        /// Host names or IP addresses for NFS Auto mount.
        /// </summary>
        public readonly ImmutableArray<string> NfsServers;

        [OutputConstructor]
        private GetBackupDestinationMountTypeDetailsResult(
            string localMountPointPath,

            string mountType,

            string nfsServerExport,

            ImmutableArray<string> nfsServers)
        {
            LocalMountPointPath = localMountPointPath;
            MountType = mountType;
            NfsServerExport = nfsServerExport;
            NfsServers = nfsServers;
        }
    }
}
