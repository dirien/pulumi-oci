// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetManagedDatabasesManagedDatabaseCollectionItemResult
    {
        /// <summary>
        /// The additional details specific to a type of database defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> AdditionalDetails;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The status of the Oracle Database. Indicates whether the status of the database is UP, DOWN, or UNKNOWN at the current time.
        /// </summary>
        public readonly string DatabaseStatus;
        /// <summary>
        /// The subtype of the Oracle Database. Indicates whether the database is a Container Database, Pluggable Database, or a Non-container Database.
        /// </summary>
        public readonly string DatabaseSubType;
        /// <summary>
        /// The type of Oracle Database installation.
        /// </summary>
        public readonly string DatabaseType;
        /// <summary>
        /// The identifier of the resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether the Oracle Database is part of a cluster.
        /// </summary>
        public readonly bool IsCluster;
        /// <summary>
        /// A list of Managed Database Groups that the Managed Database belongs to.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabasesManagedDatabaseCollectionItemManagedDatabaseGroupResult> ManagedDatabaseGroups;
        /// <summary>
        /// A filter to return only resources that match the entire name.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the parent Container Database if Managed Database is a Pluggable Database.
        /// </summary>
        public readonly string ParentContainerId;
        /// <summary>
        /// The date and time the Managed Database was created.
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetManagedDatabasesManagedDatabaseCollectionItemResult(
            ImmutableDictionary<string, object> additionalDetails,

            string compartmentId,

            string databaseStatus,

            string databaseSubType,

            string databaseType,

            string id,

            bool isCluster,

            ImmutableArray<Outputs.GetManagedDatabasesManagedDatabaseCollectionItemManagedDatabaseGroupResult> managedDatabaseGroups,

            string name,

            string parentContainerId,

            string timeCreated)
        {
            AdditionalDetails = additionalDetails;
            CompartmentId = compartmentId;
            DatabaseStatus = databaseStatus;
            DatabaseSubType = databaseSubType;
            DatabaseType = databaseType;
            Id = id;
            IsCluster = isCluster;
            ManagedDatabaseGroups = managedDatabaseGroups;
            Name = name;
            ParentContainerId = parentContainerId;
            TimeCreated = timeCreated;
        }
    }
}
