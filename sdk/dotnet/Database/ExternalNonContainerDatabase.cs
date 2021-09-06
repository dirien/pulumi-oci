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
    /// This resource provides the External Non Container Database resource in Oracle Cloud Infrastructure Database service.
    /// 
    /// Creates a new ExternalNonContainerDatabase resource
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
    ///         var testExternalNonContainerDatabase = new Oci.Database.ExternalNonContainerDatabase("testExternalNonContainerDatabase", new Oci.Database.ExternalNonContainerDatabaseArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             DisplayName = @var.External_non_container_database_display_name,
    ///             DefinedTags = @var.External_non_container_database_defined_tags,
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// ExternalNonContainerDatabases can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:database/externalNonContainerDatabase:ExternalNonContainerDatabase test_external_non_container_database "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:database/externalNonContainerDatabase:ExternalNonContainerDatabase")]
    public partial class ExternalNonContainerDatabase : Pulumi.CustomResource
    {
        /// <summary>
        /// The character set of the external database.
        /// </summary>
        [Output("characterSet")]
        public Output<string> CharacterSet { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The Oracle Database configuration
        /// </summary>
        [Output("databaseConfiguration")]
        public Output<string> DatabaseConfiguration { get; private set; } = null!;

        /// <summary>
        /// The Oracle Database edition.
        /// </summary>
        [Output("databaseEdition")]
        public Output<string> DatabaseEdition { get; private set; } = null!;

        /// <summary>
        /// The configuration of the Database Management service.
        /// </summary>
        [Output("databaseManagementConfig")]
        public Output<Outputs.ExternalNonContainerDatabaseDatabaseManagementConfig> DatabaseManagementConfig { get; private set; } = null!;

        /// <summary>
        /// The Oracle Database version.
        /// </summary>
        [Output("databaseVersion")]
        public Output<string> DatabaseVersion { get; private set; } = null!;

        /// <summary>
        /// The Oracle Database ID, which identifies an Oracle Database located outside of Oracle Cloud.
        /// </summary>
        [Output("dbId")]
        public Output<string> DbId { get; private set; } = null!;

        /// <summary>
        /// The database packs licensed for the external Oracle Database.
        /// </summary>
        [Output("dbPacks")]
        public Output<string> DbPacks { get; private set; } = null!;

        /// <summary>
        /// The `DB_UNIQUE_NAME` of the external database.
        /// </summary>
        [Output("dbUniqueName")]
        public Output<string> DbUniqueName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The user-friendly name for the external database. The name does not have to be unique.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The national character of the external database.
        /// </summary>
        [Output("ncharacterSet")]
        public Output<string> NcharacterSet { get; private set; } = null!;

        /// <summary>
        /// The configuration of Operations Insights for the external database
        /// </summary>
        [Output("operationsInsightsConfig")]
        public Output<Outputs.ExternalNonContainerDatabaseOperationsInsightsConfig> OperationsInsightsConfig { get; private set; } = null!;

        /// <summary>
        /// The current state of the Oracle Cloud Infrastructure external database resource.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the database was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time zone of the external database. It is a time zone offset (a character type in the format '[+|-]TZH:TZM') or a time zone region name, depending on how the time zone value was specified when the database was created / last altered.
        /// </summary>
        [Output("timeZone")]
        public Output<string> TimeZone { get; private set; } = null!;


        /// <summary>
        /// Create a ExternalNonContainerDatabase resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ExternalNonContainerDatabase(string name, ExternalNonContainerDatabaseArgs args, CustomResourceOptions? options = null)
            : base("oci:database/externalNonContainerDatabase:ExternalNonContainerDatabase", name, args ?? new ExternalNonContainerDatabaseArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ExternalNonContainerDatabase(string name, Input<string> id, ExternalNonContainerDatabaseState? state = null, CustomResourceOptions? options = null)
            : base("oci:database/externalNonContainerDatabase:ExternalNonContainerDatabase", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ExternalNonContainerDatabase resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ExternalNonContainerDatabase Get(string name, Input<string> id, ExternalNonContainerDatabaseState? state = null, CustomResourceOptions? options = null)
        {
            return new ExternalNonContainerDatabase(name, id, state, options);
        }
    }

    public sealed class ExternalNonContainerDatabaseArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

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
        /// (Updatable) The user-friendly name for the external database. The name does not have to be unique.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

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

        public ExternalNonContainerDatabaseArgs()
        {
        }
    }

    public sealed class ExternalNonContainerDatabaseState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The character set of the external database.
        /// </summary>
        [Input("characterSet")]
        public Input<string>? CharacterSet { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The Oracle Database configuration
        /// </summary>
        [Input("databaseConfiguration")]
        public Input<string>? DatabaseConfiguration { get; set; }

        /// <summary>
        /// The Oracle Database edition.
        /// </summary>
        [Input("databaseEdition")]
        public Input<string>? DatabaseEdition { get; set; }

        /// <summary>
        /// The configuration of the Database Management service.
        /// </summary>
        [Input("databaseManagementConfig")]
        public Input<Inputs.ExternalNonContainerDatabaseDatabaseManagementConfigGetArgs>? DatabaseManagementConfig { get; set; }

        /// <summary>
        /// The Oracle Database version.
        /// </summary>
        [Input("databaseVersion")]
        public Input<string>? DatabaseVersion { get; set; }

        /// <summary>
        /// The Oracle Database ID, which identifies an Oracle Database located outside of Oracle Cloud.
        /// </summary>
        [Input("dbId")]
        public Input<string>? DbId { get; set; }

        /// <summary>
        /// The database packs licensed for the external Oracle Database.
        /// </summary>
        [Input("dbPacks")]
        public Input<string>? DbPacks { get; set; }

        /// <summary>
        /// The `DB_UNIQUE_NAME` of the external database.
        /// </summary>
        [Input("dbUniqueName")]
        public Input<string>? DbUniqueName { get; set; }

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
        /// (Updatable) The user-friendly name for the external database. The name does not have to be unique.
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
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The national character of the external database.
        /// </summary>
        [Input("ncharacterSet")]
        public Input<string>? NcharacterSet { get; set; }

        /// <summary>
        /// The configuration of Operations Insights for the external database
        /// </summary>
        [Input("operationsInsightsConfig")]
        public Input<Inputs.ExternalNonContainerDatabaseOperationsInsightsConfigGetArgs>? OperationsInsightsConfig { get; set; }

        /// <summary>
        /// The current state of the Oracle Cloud Infrastructure external database resource.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the database was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time zone of the external database. It is a time zone offset (a character type in the format '[+|-]TZH:TZM') or a time zone region name, depending on how the time zone value was specified when the database was created / last altered.
        /// </summary>
        [Input("timeZone")]
        public Input<string>? TimeZone { get; set; }

        public ExternalNonContainerDatabaseState()
        {
        }
    }
}
