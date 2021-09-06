// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class DatabaseDatabaseArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// A strong password for SYS, SYSTEM, PDB Admin and TDE Wallet. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
        /// </summary>
        [Input("adminPassword", required: true)]
        public Input<string> AdminPassword { get; set; } = null!;

        /// <summary>
        /// The backup [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("backupId")]
        public Input<string>? BackupId { get; set; }

        /// <summary>
        /// The password to open the TDE wallet.
        /// </summary>
        [Input("backupTdePassword")]
        public Input<string>? BackupTdePassword { get; set; }

        /// <summary>
        /// The character set for the database.  The default is AL32UTF8. Allowed values are:
        /// </summary>
        [Input("characterSet")]
        public Input<string>? CharacterSet { get; set; }

        /// <summary>
        /// The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Input("databaseSoftwareImageId")]
        public Input<string>? DatabaseSoftwareImageId { get; set; }

        /// <summary>
        /// (Updatable) Backup Options To use any of the API operations, you must be authorized in an IAM policy. If you're not authorized, talk to an administrator. If you're an administrator who needs to write policies to give users access, see [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
        /// </summary>
        [Input("dbBackupConfig")]
        public Input<Inputs.DatabaseDatabaseDbBackupConfigArgs>? DbBackupConfig { get; set; }

        /// <summary>
        /// The display name of the database to be created from the backup. It must begin with an alphabetic character and can contain a maximum of eight alphanumeric characters. Special characters are not permitted.
        /// </summary>
        [Input("dbName", required: true)]
        public Input<string> DbName { get; set; } = null!;

        /// <summary>
        /// The `DB_UNIQUE_NAME` of the Oracle Database being backed up.
        /// </summary>
        [Input("dbUniqueName")]
        public Input<string>? DbUniqueName { get; set; }

        /// <summary>
        /// The database workload type.
        /// </summary>
        [Input("dbWorkload")]
        public Input<string>? DbWorkload { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The national character set for the database.  The default is AL16UTF16. Allowed values are: AL16UTF16 or UTF8.
        /// </summary>
        [Input("ncharacterSet")]
        public Input<string>? NcharacterSet { get; set; }

        /// <summary>
        /// The name of the pluggable database. The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. Pluggable database should not be same as database name.
        /// </summary>
        [Input("pdbName")]
        public Input<string>? PdbName { get; set; }

        /// <summary>
        /// The optional password to open the TDE wallet. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numeric, and two special characters. The special characters must be _, \#, or -.
        /// </summary>
        [Input("tdeWalletPassword")]
        public Input<string>? TdeWalletPassword { get; set; }

        public DatabaseDatabaseArgs()
        {
        }
    }
}
