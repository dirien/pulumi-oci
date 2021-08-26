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
    public sealed class GetAutonomousDatabaseDataguardAssociationsAutonomousDatabaseDataguardAssociationResult
    {
        /// <summary>
        /// The lag time between updates to the primary database and application of the redo data on the standby database, as computed by the reporting database.  Example: `9 seconds`
        /// </summary>
        public readonly string ApplyLag;
        /// <summary>
        /// The rate at which redo logs are synced between the associated databases.  Example: `180 Mb per second`
        /// </summary>
        public readonly string ApplyRate;
        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string AutonomousDatabaseId;
        /// <summary>
        /// The OCID of the Autonomous Dataguard created for Autonomous Container Database where given Autonomous Database resides in.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Additional information about the current lifecycleState, if available.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Database.
        /// </summary>
        public readonly string PeerAutonomousDatabaseId;
        /// <summary>
        /// The current state of Autonomous Data Guard.
        /// </summary>
        public readonly string PeerAutonomousDatabaseLifeCycleState;
        /// <summary>
        /// The Data Guard role of the Autonomous Container Database, if Autonomous Data Guard is enabled.
        /// </summary>
        public readonly string PeerRole;
        /// <summary>
        /// The protection mode of this Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
        /// </summary>
        public readonly string ProtectionMode;
        /// <summary>
        /// The Data Guard role of the Autonomous Container Database, if Autonomous Data Guard is enabled.
        /// </summary>
        public readonly string Role;
        /// <summary>
        /// The current state of Autonomous Data Guard.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the Data Guard association was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time when the last role change action happened.
        /// </summary>
        public readonly string TimeLastRoleChanged;
        /// <summary>
        /// The date and time of the last update to the apply lag, apply rate, and transport lag values.
        /// </summary>
        public readonly string TimeLastSynced;
        /// <summary>
        /// The approximate number of seconds of redo data not yet available on the standby Autonomous Container Database, as computed by the reporting database.  Example: `7 seconds`
        /// </summary>
        public readonly string TransportLag;

        [OutputConstructor]
        private GetAutonomousDatabaseDataguardAssociationsAutonomousDatabaseDataguardAssociationResult(
            string applyLag,

            string applyRate,

            string autonomousDatabaseId,

            string id,

            string lifecycleDetails,

            string peerAutonomousDatabaseId,

            string peerAutonomousDatabaseLifeCycleState,

            string peerRole,

            string protectionMode,

            string role,

            string state,

            string timeCreated,

            string timeLastRoleChanged,

            string timeLastSynced,

            string transportLag)
        {
            ApplyLag = applyLag;
            ApplyRate = applyRate;
            AutonomousDatabaseId = autonomousDatabaseId;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            PeerAutonomousDatabaseId = peerAutonomousDatabaseId;
            PeerAutonomousDatabaseLifeCycleState = peerAutonomousDatabaseLifeCycleState;
            PeerRole = peerRole;
            ProtectionMode = protectionMode;
            Role = role;
            State = state;
            TimeCreated = timeCreated;
            TimeLastRoleChanged = timeLastRoleChanged;
            TimeLastSynced = timeLastSynced;
            TransportLag = transportLag;
        }
    }
}
