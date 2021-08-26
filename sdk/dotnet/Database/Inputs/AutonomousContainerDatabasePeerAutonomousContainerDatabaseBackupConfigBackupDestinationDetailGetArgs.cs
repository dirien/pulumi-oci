// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class AutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfigBackupDestinationDetailGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// Proxy URL to connect to object store.
        /// </summary>
        [Input("internetProxy")]
        public Input<string>? InternetProxy { get; set; }

        /// <summary>
        /// Type of the database backup destination.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        /// <summary>
        /// For a RECOVERY_APPLIANCE backup destination, the password for the VPC user that is used to access the Recovery Appliance.
        /// </summary>
        [Input("vpcPassword")]
        public Input<string>? VpcPassword { get; set; }

        /// <summary>
        /// For a RECOVERY_APPLIANCE backup destination, the Virtual Private Catalog (VPC) user that is used to access the Recovery Appliance.
        /// </summary>
        [Input("vpcUser")]
        public Input<string>? VpcUser { get; set; }

        public AutonomousContainerDatabasePeerAutonomousContainerDatabaseBackupConfigBackupDestinationDetailGetArgs()
        {
        }
    }
}
