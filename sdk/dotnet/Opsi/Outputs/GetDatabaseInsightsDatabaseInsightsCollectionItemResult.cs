// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi.Outputs
{

    [OutputType]
    public sealed class GetDatabaseInsightsDatabaseInsightsCollectionItemResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly string DatabaseDisplayName;
        /// <summary>
        /// Optional list of database [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated DBaaS entity.
        /// </summary>
        public readonly string DatabaseId;
        public readonly string DatabaseName;
        /// <summary>
        /// Filter by one or more database type. Possible values are ADW-S, ATP-S, ADW-D, ATP-D, EXTERNAL-PDB, EXTERNAL-NONCDB.
        /// </summary>
        public readonly string DatabaseType;
        /// <summary>
        /// The version of the database.
        /// </summary>
        public readonly string DatabaseVersion;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Unique Enterprise Manager bridge identifier
        /// </summary>
        public readonly string EnterpriseManagerBridgeId;
        /// <summary>
        /// Enterprise Manager Entity Display Name
        /// </summary>
        public readonly string EnterpriseManagerEntityDisplayName;
        /// <summary>
        /// Enterprise Manager Entity Unique Identifier
        /// </summary>
        public readonly string EnterpriseManagerEntityIdentifier;
        /// <summary>
        /// Enterprise Manager Entity Name
        /// </summary>
        public readonly string EnterpriseManagerEntityName;
        /// <summary>
        /// Enterprise Manager Entity Type
        /// </summary>
        public readonly string EnterpriseManagerEntityType;
        /// <summary>
        /// Enterprise Manager Unqiue Identifier
        /// </summary>
        public readonly string EnterpriseManagerIdentifier;
        /// <summary>
        /// Source of the database entity.
        /// </summary>
        public readonly string EntitySource;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Optional database insight resource [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database insight resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Processor count.
        /// </summary>
        public readonly int ProcessorCount;
        /// <summary>
        /// Lifecycle states
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Resource Status
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The time the the database insight was first enabled. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the database insight was updated. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDatabaseInsightsDatabaseInsightsCollectionItemResult(
            string compartmentId,

            string databaseDisplayName,

            string databaseId,

            string databaseName,

            string databaseType,

            string databaseVersion,

            ImmutableDictionary<string, object> definedTags,

            string enterpriseManagerBridgeId,

            string enterpriseManagerEntityDisplayName,

            string enterpriseManagerEntityIdentifier,

            string enterpriseManagerEntityName,

            string enterpriseManagerEntityType,

            string enterpriseManagerIdentifier,

            string entitySource,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            int processorCount,

            string state,

            string status,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DatabaseDisplayName = databaseDisplayName;
            DatabaseId = databaseId;
            DatabaseName = databaseName;
            DatabaseType = databaseType;
            DatabaseVersion = databaseVersion;
            DefinedTags = definedTags;
            EnterpriseManagerBridgeId = enterpriseManagerBridgeId;
            EnterpriseManagerEntityDisplayName = enterpriseManagerEntityDisplayName;
            EnterpriseManagerEntityIdentifier = enterpriseManagerEntityIdentifier;
            EnterpriseManagerEntityName = enterpriseManagerEntityName;
            EnterpriseManagerEntityType = enterpriseManagerEntityType;
            EnterpriseManagerIdentifier = enterpriseManagerIdentifier;
            EntitySource = entitySource;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            ProcessorCount = processorCount;
            State = state;
            Status = status;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
