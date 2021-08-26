// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Inputs
{

    public sealed class MigrationVaultDetailsGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) OCID of the compartment where the secret containing the credentials will be created.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// (Updatable) OCID of the vault encryption key
        /// </summary>
        [Input("keyId", required: true)]
        public Input<string> KeyId { get; set; } = null!;

        /// <summary>
        /// (Updatable) OCID of the vault
        /// </summary>
        [Input("vaultId", required: true)]
        public Input<string> VaultId { get; set; } = null!;

        public MigrationVaultDetailsGetArgs()
        {
        }
    }
}
