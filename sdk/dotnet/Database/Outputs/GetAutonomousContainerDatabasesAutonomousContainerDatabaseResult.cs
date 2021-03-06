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
    public sealed class GetAutonomousContainerDatabasesAutonomousContainerDatabaseResult
    {
        /// <summary>
        /// The Autonomous Exadata Infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string AutonomousExadataInfrastructureId;
        /// <summary>
        /// The Autonomous VM Cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string AutonomousVmClusterId;
        /// <summary>
        /// A filter to return only resources that match the given availability domain exactly.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// Backup options for the Autonomous Container Database.
        /// </summary>
        public readonly Outputs.GetAutonomousContainerDatabasesAutonomousContainerDatabaseBackupConfigResult BackupConfig;
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The `DB_UNIQUE_NAME` of the Oracle Database being backed up.
        /// </summary>
        public readonly string DbUniqueName;
        /// <summary>
        /// Oracle Database version of the Autonomous Container Database.
        /// </summary>
        public readonly string DbVersion;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The OCID of the Autonomous Container Database.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A filter to return only resources that match the given Infrastructure Type.
        /// </summary>
        public readonly string InfrastructureType;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
        /// </summary>
        public readonly string KeyStoreId;
        /// <summary>
        /// The wallet name for Oracle Key Vault.
        /// </summary>
        public readonly string KeyStoreWalletName;
        /// <summary>
        /// The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
        /// </summary>
        public readonly string KmsKeyId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance run.
        /// </summary>
        public readonly string LastMaintenanceRunId;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
        /// </summary>
        public readonly Outputs.GetAutonomousContainerDatabasesAutonomousContainerDatabaseMaintenanceWindowResult MaintenanceWindow;
        public readonly Outputs.GetAutonomousContainerDatabasesAutonomousContainerDatabaseMaintenanceWindowDetailsResult MaintenanceWindowDetails;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the next maintenance run.
        /// </summary>
        public readonly string NextMaintenanceRunId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch applied on the system.
        /// </summary>
        public readonly string PatchId;
        /// <summary>
        /// Database patch model preference.
        /// </summary>
        public readonly string PatchModel;
        public readonly Outputs.GetAutonomousContainerDatabasesAutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfigResult PeerAutonomousContainerDatabaseBackupConfig;
        public readonly string PeerAutonomousContainerDatabaseCompartmentId;
        public readonly string PeerAutonomousContainerDatabaseDisplayName;
        public readonly string PeerAutonomousExadataInfrastructureId;
        public readonly string PeerAutonomousVmClusterId;
        public readonly string PeerDbUniqueName;
        public readonly string ProtectionMode;
        /// <summary>
        /// The role of the dataguard enabled Autonomous Container Database.
        /// </summary>
        public readonly string Role;
        public readonly bool RotateKeyTrigger;
        /// <summary>
        /// A filter to return only resources that match the given service level agreement type exactly.
        /// </summary>
        public readonly string ServiceLevelAgreementType;
        /// <summary>
        /// The scheduling detail for the quarterly maintenance window of the standby Autonomous Container Database. This value represents the number of days before scheduled maintenance of the primary database.
        /// </summary>
        public readonly int StandbyMaintenanceBufferInDays;
        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the Autonomous Container Database was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [vault](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
        /// </summary>
        public readonly string VaultId;

        [OutputConstructor]
        private GetAutonomousContainerDatabasesAutonomousContainerDatabaseResult(
            string autonomousExadataInfrastructureId,

            string autonomousVmClusterId,

            string availabilityDomain,

            Outputs.GetAutonomousContainerDatabasesAutonomousContainerDatabaseBackupConfigResult backupConfig,

            string compartmentId,

            string dbUniqueName,

            string dbVersion,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string infrastructureType,

            string keyStoreId,

            string keyStoreWalletName,

            string kmsKeyId,

            string lastMaintenanceRunId,

            string lifecycleDetails,

            Outputs.GetAutonomousContainerDatabasesAutonomousContainerDatabaseMaintenanceWindowResult maintenanceWindow,

            Outputs.GetAutonomousContainerDatabasesAutonomousContainerDatabaseMaintenanceWindowDetailsResult maintenanceWindowDetails,

            string nextMaintenanceRunId,

            string patchId,

            string patchModel,

            Outputs.GetAutonomousContainerDatabasesAutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfigResult peerAutonomousContainerDatabaseBackupConfig,

            string peerAutonomousContainerDatabaseCompartmentId,

            string peerAutonomousContainerDatabaseDisplayName,

            string peerAutonomousExadataInfrastructureId,

            string peerAutonomousVmClusterId,

            string peerDbUniqueName,

            string protectionMode,

            string role,

            bool rotateKeyTrigger,

            string serviceLevelAgreementType,

            int standbyMaintenanceBufferInDays,

            string state,

            string timeCreated,

            string vaultId)
        {
            AutonomousExadataInfrastructureId = autonomousExadataInfrastructureId;
            AutonomousVmClusterId = autonomousVmClusterId;
            AvailabilityDomain = availabilityDomain;
            BackupConfig = backupConfig;
            CompartmentId = compartmentId;
            DbUniqueName = dbUniqueName;
            DbVersion = dbVersion;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            InfrastructureType = infrastructureType;
            KeyStoreId = keyStoreId;
            KeyStoreWalletName = keyStoreWalletName;
            KmsKeyId = kmsKeyId;
            LastMaintenanceRunId = lastMaintenanceRunId;
            LifecycleDetails = lifecycleDetails;
            MaintenanceWindow = maintenanceWindow;
            MaintenanceWindowDetails = maintenanceWindowDetails;
            NextMaintenanceRunId = nextMaintenanceRunId;
            PatchId = patchId;
            PatchModel = patchModel;
            PeerAutonomousContainerDatabaseBackupConfig = peerAutonomousContainerDatabaseBackupConfig;
            PeerAutonomousContainerDatabaseCompartmentId = peerAutonomousContainerDatabaseCompartmentId;
            PeerAutonomousContainerDatabaseDisplayName = peerAutonomousContainerDatabaseDisplayName;
            PeerAutonomousExadataInfrastructureId = peerAutonomousExadataInfrastructureId;
            PeerAutonomousVmClusterId = peerAutonomousVmClusterId;
            PeerDbUniqueName = peerDbUniqueName;
            ProtectionMode = protectionMode;
            Role = role;
            RotateKeyTrigger = rotateKeyTrigger;
            ServiceLevelAgreementType = serviceLevelAgreementType;
            StandbyMaintenanceBufferInDays = standbyMaintenanceBufferInDays;
            State = state;
            TimeCreated = timeCreated;
            VaultId = vaultId;
        }
    }
}
