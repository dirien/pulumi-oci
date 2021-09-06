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
    public sealed class DbHomeDatabaseDbBackupConfigBackupDestinationDetail
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// Type of the database backup destination. Supported values: `NFS`.
        /// </summary>
        public readonly string? Type;

        [OutputConstructor]
        private DbHomeDatabaseDbBackupConfigBackupDestinationDetail(
            string? id,

            string? type)
        {
            Id = id;
            Type = type;
        }
    }
}
