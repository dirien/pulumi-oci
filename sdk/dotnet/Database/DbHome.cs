// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    /// <summary>
    /// This resource provides the Db Home resource in Oracle Cloud Infrastructure Database service.
    /// 
    /// Creates a new Database Home in the specified database system based on the request parameters you provide. Applies only to bare metal and Exadata systems.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testDbHome = new Oci.Database.DbHome("testDbHome", new Oci.Database.DbHomeArgs
    ///         {
    ///             Database = new Oci.Database.Inputs.DbHomeDatabaseArgs
    ///             {
    ///                 AdminPassword = @var.Db_home_database_admin_password,
    ///                 BackupId = oci_database_backup.Test_backup.Id,
    ///                 BackupTdePassword = @var.Db_home_database_backup_tde_password,
    ///                 CharacterSet = @var.Db_home_database_character_set,
    ///                 DatabaseId = oci_database_database.Test_database.Id,
    ///                 DatabaseSoftwareImageId = oci_database_database_software_image.Test_database_software_image.Id,
    ///                 DbBackupConfig = new Oci.Database.Inputs.DbHomeDatabaseDbBackupConfigArgs
    ///                 {
    ///                     AutoBackupEnabled = @var.Db_home_database_db_backup_config_auto_backup_enabled,
    ///                     AutoBackupWindow = @var.Db_home_database_db_backup_config_auto_backup_window,
    ///                     BackupDestinationDetails = 
    ///                     {
    ///                         new Oci.Database.Inputs.DbHomeDatabaseDbBackupConfigBackupDestinationDetailArgs
    ///                         {
    ///                             Id = @var.Db_home_database_db_backup_config_backup_destination_details_id,
    ///                             Type = @var.Db_home_database_db_backup_config_backup_destination_details_type,
    ///                         },
    ///                     },
    ///                     RecoveryWindowInDays = @var.Db_home_database_db_backup_config_recovery_window_in_days,
    ///                 },
    ///                 DbName = @var.Db_home_database_db_name,
    ///                 DbWorkload = @var.Db_home_database_db_workload,
    ///                 DefinedTags = @var.Db_home_database_defined_tags,
    ///                 FreeformTags = @var.Db_home_database_freeform_tags,
    ///                 NcharacterSet = @var.Db_home_database_ncharacter_set,
    ///                 PdbName = @var.Db_home_database_pdb_name,
    ///                 TdeWalletPassword = @var.Db_home_database_tde_wallet_password,
    ///                 TimeStampForPointInTimeRecovery = @var.Db_home_database_time_stamp_for_point_in_time_recovery,
    ///             },
    ///             DatabaseSoftwareImageId = oci_database_database_software_image.Test_database_software_image.Id,
    ///             DbSystemId = oci_database_db_system.Test_db_system.Id,
    ///             DbVersion = 
    ///             {
    ///                 ,
    ///             },
    ///             DefinedTags = @var.Db_home_defined_tags,
    ///             DisplayName = @var.Db_home_display_name,
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///             IsDesupportedVersion = @var.Db_home_is_desupported_version,
    ///             KmsKeyId = oci_kms_key.Test_key.Id,
    ///             KmsKeyVersionId = oci_kms_key_version.Test_key_version.Id,
    ///             Source = @var.Db_home_source,
    ///             VmClusterId = oci_database_vm_cluster.Test_vm_cluster.Id,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// DbHomes can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:database/dbHome:DbHome test_db_home "id"
    /// ```
    /// 
    ///  Import is only supported for source=NONE database.0.admin_password is not returned by the service for security reasons. Add the following to the resource:
    /// 
    ///  lifecycle {
    /// 
    ///  ignore_changes = ["database.0.admin_password"]
    /// 
    ///  } The creation of an oci_database_db_system requires that it be created with exactly one oci_database_db_home. Therefore the first db home will have to be a property of the db system resource and any further db homes to be added to the db system will have to be added as first class resources using "oci_database_db_home".
    /// </summary>
    [OciResourceType("oci:database/dbHome:DbHome")]
    public partial class DbHome : Pulumi.CustomResource
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Details for creating a database.
        /// </summary>
        [Output("database")]
        public Output<Outputs.DbHomeDatabase> Database { get; private set; } = null!;

        /// <summary>
        /// The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Output("databaseSoftwareImageId")]
        public Output<string> DatabaseSoftwareImageId { get; private set; } = null!;

        /// <summary>
        /// The location of the Oracle Database Home.
        /// </summary>
        [Output("dbHomeLocation")]
        public Output<string> DbHomeLocation { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
        /// </summary>
        [Output("dbSystemId")]
        public Output<string> DbSystemId { get; private set; } = null!;

        /// <summary>
        /// A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        [Output("dbVersion")]
        public Output<string> DbVersion { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// The user-provided name of the Database Home.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// If true, the customer acknowledges that the specified Oracle Database software is an older release that is not currently supported by OCI.
        /// </summary>
        [Output("isDesupportedVersion")]
        public Output<bool> IsDesupportedVersion { get; private set; } = null!;

        /// <summary>
        /// The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
        /// </summary>
        [Output("kmsKeyId")]
        public Output<string> KmsKeyId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation.
        /// </summary>
        [Output("kmsKeyVersionId")]
        public Output<string> KmsKeyVersionId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch history. This value is updated as soon as a patch operation is started.
        /// </summary>
        [Output("lastPatchHistoryEntryId")]
        public Output<string> LastPatchHistoryEntryId { get; private set; } = null!;

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The source of database: NONE for creating a new database. DB_BACKUP for creating a new database by restoring from a database backup. VM_CLUSTER_NEW for creating a database for VM Cluster.
        /// </summary>
        [Output("source")]
        public Output<string> Source { get; private set; } = null!;

        /// <summary>
        /// The current state of the Database Home.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the Database Home was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
        /// </summary>
        [Output("vmClusterId")]
        public Output<string> VmClusterId { get; private set; } = null!;


        /// <summary>
        /// Create a DbHome resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DbHome(string name, DbHomeArgs args, CustomResourceOptions? options = null)
            : base("oci:database/dbHome:DbHome", name, args ?? new DbHomeArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DbHome(string name, Input<string> id, DbHomeState? state = null, CustomResourceOptions? options = null)
            : base("oci:database/dbHome:DbHome", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing DbHome resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DbHome Get(string name, Input<string> id, DbHomeState? state = null, CustomResourceOptions? options = null)
        {
            return new DbHome(name, id, state, options);
        }
    }

    public sealed class DbHomeArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Details for creating a database.
        /// </summary>
        [Input("database", required: true)]
        public Input<Inputs.DbHomeDatabaseArgs> Database { get; set; } = null!;

        /// <summary>
        /// The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Input("databaseSoftwareImageId")]
        public Input<string>? DatabaseSoftwareImageId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
        /// </summary>
        [Input("dbSystemId")]
        public Input<string>? DbSystemId { get; set; }

        /// <summary>
        /// A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        [Input("dbVersion")]
        public Input<string>? DbVersion { get; set; }

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

        /// <summary>
        /// The user-provided name of the Database Home.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

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
        /// If true, the customer acknowledges that the specified Oracle Database software is an older release that is not currently supported by OCI.
        /// </summary>
        [Input("isDesupportedVersion")]
        public Input<bool>? IsDesupportedVersion { get; set; }

        /// <summary>
        /// The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
        /// </summary>
        [Input("kmsKeyId")]
        public Input<string>? KmsKeyId { get; set; }

        /// <summary>
        /// The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation.
        /// </summary>
        [Input("kmsKeyVersionId")]
        public Input<string>? KmsKeyVersionId { get; set; }

        /// <summary>
        /// The source of database: NONE for creating a new database. DB_BACKUP for creating a new database by restoring from a database backup. VM_CLUSTER_NEW for creating a database for VM Cluster.
        /// </summary>
        [Input("source")]
        public Input<string>? Source { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
        /// </summary>
        [Input("vmClusterId")]
        public Input<string>? VmClusterId { get; set; }

        public DbHomeArgs()
        {
        }
    }

    public sealed class DbHomeState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) Details for creating a database.
        /// </summary>
        [Input("database")]
        public Input<Inputs.DbHomeDatabaseGetArgs>? Database { get; set; }

        /// <summary>
        /// The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Input("databaseSoftwareImageId")]
        public Input<string>? DatabaseSoftwareImageId { get; set; }

        /// <summary>
        /// The location of the Oracle Database Home.
        /// </summary>
        [Input("dbHomeLocation")]
        public Input<string>? DbHomeLocation { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
        /// </summary>
        [Input("dbSystemId")]
        public Input<string>? DbSystemId { get; set; }

        /// <summary>
        /// A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        [Input("dbVersion")]
        public Input<string>? DbVersion { get; set; }

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

        /// <summary>
        /// The user-provided name of the Database Home.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

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
        /// If true, the customer acknowledges that the specified Oracle Database software is an older release that is not currently supported by OCI.
        /// </summary>
        [Input("isDesupportedVersion")]
        public Input<bool>? IsDesupportedVersion { get; set; }

        /// <summary>
        /// The OCID of the key container that is used as the master encryption key in database transparent data encryption (TDE) operations.
        /// </summary>
        [Input("kmsKeyId")]
        public Input<string>? KmsKeyId { get; set; }

        /// <summary>
        /// The OCID of the key container version that is used in database transparent data encryption (TDE) operations KMS Key can have multiple key versions. If none is specified, the current key version (latest) of the Key Id is used for the operation.
        /// </summary>
        [Input("kmsKeyVersionId")]
        public Input<string>? KmsKeyVersionId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch history. This value is updated as soon as a patch operation is started.
        /// </summary>
        [Input("lastPatchHistoryEntryId")]
        public Input<string>? LastPatchHistoryEntryId { get; set; }

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The source of database: NONE for creating a new database. DB_BACKUP for creating a new database by restoring from a database backup. VM_CLUSTER_NEW for creating a database for VM Cluster.
        /// </summary>
        [Input("source")]
        public Input<string>? Source { get; set; }

        /// <summary>
        /// The current state of the Database Home.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the Database Home was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
        /// </summary>
        [Input("vmClusterId")]
        public Input<string>? VmClusterId { get; set; }

        public DbHomeState()
        {
        }
    }
}
