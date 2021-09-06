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
    public sealed class GetMigrationsMigrationCollectionItemVaultDetailsResult
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// OCID of the vault encryption key
        /// </summary>
        public readonly string KeyId;
        /// <summary>
        /// OCID of the vault
        /// </summary>
        public readonly string VaultId;

        [OutputConstructor]
        private GetMigrationsMigrationCollectionItemVaultDetailsResult(
            string compartmentId,

            string keyId,

            string vaultId)
        {
            CompartmentId = compartmentId;
            KeyId = keyId;
            VaultId = vaultId;
        }
    }
}
