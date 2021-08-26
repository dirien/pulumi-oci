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
    public sealed class GetBackupDestinationAssociatedDatabaseResult
    {
        /// <summary>
        /// The display name of the database that is associated with the backup destination.
        /// </summary>
        public readonly string DbName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetBackupDestinationAssociatedDatabaseResult(
            string dbName,

            string id)
        {
            DbName = dbName;
            Id = id;
        }
    }
}
