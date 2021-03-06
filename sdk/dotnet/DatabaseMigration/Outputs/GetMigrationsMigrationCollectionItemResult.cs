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
    public sealed class GetMigrationsMigrationCollectionItemResult
    {
        /// <summary>
        /// The OCID of the registered On-Prem ODMS Agent. Required for Offline Migrations.
        /// </summary>
        public readonly string AgentId;
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// OCID of the Secret in the Oracle Cloud Infrastructure vault containing the Migration credentials. Used to store Golden Gate admin user credentials.
        /// </summary>
        public readonly string CredentialsSecretId;
        /// <summary>
        /// Data Transfer Medium details for the Migration.
        /// </summary>
        public readonly Outputs.GetMigrationsMigrationCollectionItemDataTransferMediumDetailsResult DataTransferMediumDetails;
        /// <summary>
        /// Optional settings for Datapump Export and Import jobs
        /// </summary>
        public readonly Outputs.GetMigrationsMigrationCollectionItemDatapumpSettingsResult DatapumpSettings;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Database objects to exclude from migration.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemExcludeObjectResult> ExcludeObjects;
        /// <summary>
        /// OCID of the current ODMS Job in execution for the Migration, if any.
        /// </summary>
        public readonly string ExecutingJobId;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Details about Oracle GoldenGate Microservices.
        /// </summary>
        public readonly Outputs.GetMigrationsMigrationCollectionItemGoldenGateDetailsResult GoldenGateDetails;
        /// <summary>
        /// The OCID of the resource
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The lifecycle detailed status of the Migration.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The OCID of the Source Container Database Connection.
        /// </summary>
        public readonly string SourceContainerDatabaseConnectionId;
        /// <summary>
        /// The OCID of the Source Database Connection.
        /// </summary>
        public readonly string SourceDatabaseConnectionId;
        /// <summary>
        /// The current state of the Database Migration Deployment.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The OCID of the Target Database Connection.
        /// </summary>
        public readonly string TargetDatabaseConnectionId;
        /// <summary>
        /// The time the Migration was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time of last Migration. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeLastMigration;
        /// <summary>
        /// The time of the last Migration details update. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Migration type.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// Oracle Cloud Infrastructure Vault details to store migration and connection credentials secrets
        /// </summary>
        public readonly Outputs.GetMigrationsMigrationCollectionItemVaultDetailsResult VaultDetails;
        /// <summary>
        /// Name of a migration phase. The Job will wait after executing this phase until the Resume Job endpoint is called.
        /// </summary>
        public readonly string WaitAfter;

        [OutputConstructor]
        private GetMigrationsMigrationCollectionItemResult(
            string agentId,

            string compartmentId,

            string credentialsSecretId,

            Outputs.GetMigrationsMigrationCollectionItemDataTransferMediumDetailsResult dataTransferMediumDetails,

            Outputs.GetMigrationsMigrationCollectionItemDatapumpSettingsResult datapumpSettings,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableArray<Outputs.GetMigrationsMigrationCollectionItemExcludeObjectResult> excludeObjects,

            string executingJobId,

            ImmutableDictionary<string, object> freeformTags,

            Outputs.GetMigrationsMigrationCollectionItemGoldenGateDetailsResult goldenGateDetails,

            string id,

            string lifecycleDetails,

            string sourceContainerDatabaseConnectionId,

            string sourceDatabaseConnectionId,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string targetDatabaseConnectionId,

            string timeCreated,

            string timeLastMigration,

            string timeUpdated,

            string type,

            Outputs.GetMigrationsMigrationCollectionItemVaultDetailsResult vaultDetails,

            string waitAfter)
        {
            AgentId = agentId;
            CompartmentId = compartmentId;
            CredentialsSecretId = credentialsSecretId;
            DataTransferMediumDetails = dataTransferMediumDetails;
            DatapumpSettings = datapumpSettings;
            DefinedTags = definedTags;
            DisplayName = displayName;
            ExcludeObjects = excludeObjects;
            ExecutingJobId = executingJobId;
            FreeformTags = freeformTags;
            GoldenGateDetails = goldenGateDetails;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            SourceContainerDatabaseConnectionId = sourceContainerDatabaseConnectionId;
            SourceDatabaseConnectionId = sourceDatabaseConnectionId;
            State = state;
            SystemTags = systemTags;
            TargetDatabaseConnectionId = targetDatabaseConnectionId;
            TimeCreated = timeCreated;
            TimeLastMigration = timeLastMigration;
            TimeUpdated = timeUpdated;
            Type = type;
            VaultDetails = vaultDetails;
            WaitAfter = waitAfter;
        }
    }
}
