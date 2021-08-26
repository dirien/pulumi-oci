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
    /// This resource provides the Database Upgrade resource in Oracle Cloud Infrastructure Database service.
    /// 
    /// Upgrades the specified Oracle Database instance.
    /// 
    /// Database upgrade requires source to be `DB_VERSION` or `DB_SOFTWARE_IMAGE`.
    /// 	`db_home.0.db_version` is updated to target DB version specified in the upgrade request.
    /// 	To avoid a force new create of the db_home on the next apply, add the following to the resource
    /// 	```	lifecycle {
    /// 	   	ignore_changes = [
    /// 	   		db_home.0.db_version,
    /// 	   	]
    /// 	}
    /// 	```
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
    ///         var testDatabaseUpgrade = new Oci.Database.DatabaseUpgrade("testDatabaseUpgrade", new Oci.Database.DatabaseUpgradeArgs
    ///         {
    ///             Action = @var.Database_upgrade_action,
    ///             DatabaseId = oci_database_database.Test_database.Id,
    ///             DatabaseUpgradeSourceDetails = new Oci.Database.Inputs.DatabaseUpgradeDatabaseUpgradeSourceDetailsArgs
    ///             {
    ///                 DatabaseSoftwareImageId = oci_database_database_software_image.Test_database_software_image.Id,
    ///                 DbHomeId = oci_database_db_home.Test_db_home.Id,
    ///                 DbVersion = @var.Database_upgrade_database_upgrade_source_details_db_version,
    ///                 Options = @var.Database_upgrade_database_upgrade_source_details_options,
    ///                 Source = @var.Database_upgrade_database_upgrade_source_details_source,
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Import is not supported for this resource.
    /// </summary>
    [OciResourceType("oci:database/databaseUpgrade:DatabaseUpgrade")]
    public partial class DatabaseUpgrade : Pulumi.CustomResource
    {
        /// <summary>
        /// The database upgrade action.
        /// </summary>
        [Output("action")]
        public Output<string> Action { get; private set; } = null!;

        /// <summary>
        /// The character set for the database.
        /// </summary>
        [Output("characterSet")]
        public Output<string> CharacterSet { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The Connection strings used to connect to the Oracle Database.
        /// </summary>
        [Output("connectionStrings")]
        public Output<Outputs.DatabaseUpgradeConnectionStrings> ConnectionStrings { get; private set; } = null!;

        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Output("databaseId")]
        public Output<string> DatabaseId { get; private set; } = null!;

        /// <summary>
        /// The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the image to be used to upgrade a database.
        /// </summary>
        [Output("databaseSoftwareImageId")]
        public Output<string> DatabaseSoftwareImageId { get; private set; } = null!;

        /// <summary>
        /// Details for the database upgrade source.
        /// </summary>
        [Output("databaseUpgradeSourceDetails")]
        public Output<Outputs.DatabaseUpgradeDatabaseUpgradeSourceDetails> DatabaseUpgradeSourceDetails { get; private set; } = null!;

        /// <summary>
        /// Backup Options To use any of the API operations, you must be authorized in an IAM policy. If you're not authorized, talk to an administrator. If you're an administrator who needs to write policies to give users access, see [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
        /// </summary>
        [Output("dbBackupConfig")]
        public Output<Outputs.DatabaseUpgradeDbBackupConfig> DbBackupConfig { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
        /// </summary>
        [Output("dbHomeId")]
        public Output<string> DbHomeId { get; private set; } = null!;

        /// <summary>
        /// The database name.
        /// </summary>
        [Output("dbName")]
        public Output<string> DbName { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
        /// </summary>
        [Output("dbSystemId")]
        public Output<string> DbSystemId { get; private set; } = null!;

        /// <summary>
        /// A system-generated name for the database to ensure uniqueness within an Oracle Data Guard group (a primary database and its standby databases). The unique name cannot be changed.
        /// </summary>
        [Output("dbUniqueName")]
        public Output<string> DbUniqueName { get; private set; } = null!;

        /// <summary>
        /// The database workload type.
        /// </summary>
        [Output("dbWorkload")]
        public Output<string> DbWorkload { get; private set; } = null!;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// The date and time when the latest database backup was created.
        /// </summary>
        [Output("lastBackupTimestamp")]
        public Output<string> LastBackupTimestamp { get; private set; } = null!;

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The national character set for the database.
        /// </summary>
        [Output("ncharacterSet")]
        public Output<string> NcharacterSet { get; private set; } = null!;

        /// <summary>
        /// The name of the pluggable database. The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. Pluggable database should not be same as database name.
        /// </summary>
        [Output("pdbName")]
        public Output<string> PdbName { get; private set; } = null!;

        /// <summary>
        /// Point in time recovery timeStamp of the source database at which cloned database system is cloned from the source database system, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339)
        /// </summary>
        [Output("sourceDatabasePointInTimeRecoveryTimestamp")]
        public Output<string> SourceDatabasePointInTimeRecoveryTimestamp { get; private set; } = null!;

        /// <summary>
        /// The current state of the database.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the database was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
        /// </summary>
        [Output("vmClusterId")]
        public Output<string> VmClusterId { get; private set; } = null!;


        /// <summary>
        /// Create a DatabaseUpgrade resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DatabaseUpgrade(string name, DatabaseUpgradeArgs args, CustomResourceOptions? options = null)
            : base("oci:database/databaseUpgrade:DatabaseUpgrade", name, args ?? new DatabaseUpgradeArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DatabaseUpgrade(string name, Input<string> id, DatabaseUpgradeState? state = null, CustomResourceOptions? options = null)
            : base("oci:database/databaseUpgrade:DatabaseUpgrade", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing DatabaseUpgrade resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DatabaseUpgrade Get(string name, Input<string> id, DatabaseUpgradeState? state = null, CustomResourceOptions? options = null)
        {
            return new DatabaseUpgrade(name, id, state, options);
        }
    }

    public sealed class DatabaseUpgradeArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The database upgrade action.
        /// </summary>
        [Input("action", required: true)]
        public Input<string> Action { get; set; } = null!;

        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("databaseId", required: true)]
        public Input<string> DatabaseId { get; set; } = null!;

        /// <summary>
        /// Details for the database upgrade source.
        /// </summary>
        [Input("databaseUpgradeSourceDetails")]
        public Input<Inputs.DatabaseUpgradeDatabaseUpgradeSourceDetailsArgs>? DatabaseUpgradeSourceDetails { get; set; }

        public DatabaseUpgradeArgs()
        {
        }
    }

    public sealed class DatabaseUpgradeState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The database upgrade action.
        /// </summary>
        [Input("action")]
        public Input<string>? Action { get; set; }

        /// <summary>
        /// The character set for the database.
        /// </summary>
        [Input("characterSet")]
        public Input<string>? CharacterSet { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The Connection strings used to connect to the Oracle Database.
        /// </summary>
        [Input("connectionStrings")]
        public Input<Inputs.DatabaseUpgradeConnectionStringsGetArgs>? ConnectionStrings { get; set; }

        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("databaseId")]
        public Input<string>? DatabaseId { get; set; }

        /// <summary>
        /// The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the image to be used to upgrade a database.
        /// </summary>
        [Input("databaseSoftwareImageId")]
        public Input<string>? DatabaseSoftwareImageId { get; set; }

        /// <summary>
        /// Details for the database upgrade source.
        /// </summary>
        [Input("databaseUpgradeSourceDetails")]
        public Input<Inputs.DatabaseUpgradeDatabaseUpgradeSourceDetailsGetArgs>? DatabaseUpgradeSourceDetails { get; set; }

        /// <summary>
        /// Backup Options To use any of the API operations, you must be authorized in an IAM policy. If you're not authorized, talk to an administrator. If you're an administrator who needs to write policies to give users access, see [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
        /// </summary>
        [Input("dbBackupConfig")]
        public Input<Inputs.DatabaseUpgradeDbBackupConfigGetArgs>? DbBackupConfig { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
        /// </summary>
        [Input("dbHomeId")]
        public Input<string>? DbHomeId { get; set; }

        /// <summary>
        /// The database name.
        /// </summary>
        [Input("dbName")]
        public Input<string>? DbName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
        /// </summary>
        [Input("dbSystemId")]
        public Input<string>? DbSystemId { get; set; }

        /// <summary>
        /// A system-generated name for the database to ensure uniqueness within an Oracle Data Guard group (a primary database and its standby databases). The unique name cannot be changed.
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
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The date and time when the latest database backup was created.
        /// </summary>
        [Input("lastBackupTimestamp")]
        public Input<string>? LastBackupTimestamp { get; set; }

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The national character set for the database.
        /// </summary>
        [Input("ncharacterSet")]
        public Input<string>? NcharacterSet { get; set; }

        /// <summary>
        /// The name of the pluggable database. The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. Pluggable database should not be same as database name.
        /// </summary>
        [Input("pdbName")]
        public Input<string>? PdbName { get; set; }

        /// <summary>
        /// Point in time recovery timeStamp of the source database at which cloned database system is cloned from the source database system, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339)
        /// </summary>
        [Input("sourceDatabasePointInTimeRecoveryTimestamp")]
        public Input<string>? SourceDatabasePointInTimeRecoveryTimestamp { get; set; }

        /// <summary>
        /// The current state of the database.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the database was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
        /// </summary>
        [Input("vmClusterId")]
        public Input<string>? VmClusterId { get; set; }

        public DatabaseUpgradeState()
        {
        }
    }
}
