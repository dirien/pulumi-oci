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
    /// This resource provides the Autonomous Vm Cluster resource in Oracle Cloud Infrastructure Database service.
    /// 
    /// Creates an Autonomous VM cluster for Exadata Cloud@Customer.
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
    ///         var testAutonomousVmCluster = new Oci.Database.AutonomousVmCluster("testAutonomousVmCluster", new Oci.Database.AutonomousVmClusterArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             DisplayName = @var.Autonomous_vm_cluster_display_name,
    ///             ExadataInfrastructureId = oci_database_exadata_infrastructure.Test_exadata_infrastructure.Id,
    ///             VmClusterNetworkId = oci_database_vm_cluster_network.Test_vm_cluster_network.Id,
    ///             DefinedTags = @var.Autonomous_vm_cluster_defined_tags,
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///             IsLocalBackupEnabled = @var.Autonomous_vm_cluster_is_local_backup_enabled,
    ///             LicenseModel = @var.Autonomous_vm_cluster_license_model,
    ///             TimeZone = @var.Autonomous_vm_cluster_time_zone,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// AutonomousVmClusters can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:database/autonomousVmCluster:AutonomousVmCluster test_autonomous_vm_cluster "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:database/autonomousVmCluster:AutonomousVmCluster")]
    public partial class AutonomousVmCluster : Pulumi.CustomResource
    {
        /// <summary>
        /// The numnber of CPU cores available.
        /// </summary>
        [Output("availableCpus")]
        public Output<int> AvailableCpus { get; private set; } = null!;

        /// <summary>
        /// The data storage available in TBs
        /// </summary>
        [Output("availableDataStorageSizeInTbs")]
        public Output<double> AvailableDataStorageSizeInTbs { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The number of enabled CPU cores.
        /// </summary>
        [Output("cpusEnabled")]
        public Output<int> CpusEnabled { get; private set; } = null!;

        /// <summary>
        /// The total data storage allocated in TBs
        /// </summary>
        [Output("dataStorageSizeInTbs")]
        public Output<double> DataStorageSizeInTbs { get; private set; } = null!;

        /// <summary>
        /// The local node storage allocated in GBs.
        /// </summary>
        [Output("dbNodeStorageSizeInGbs")]
        public Output<int> DbNodeStorageSizeInGbs { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// The user-friendly name for the Autonomous VM cluster. The name does not need to be unique.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
        /// </summary>
        [Output("exadataInfrastructureId")]
        public Output<string> ExadataInfrastructureId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// If true, database backup on local Exadata storage is configured for the Autonomous VM cluster. If false, database backup on local Exadata storage is not available in the Autonomous VM cluster.
        /// </summary>
        [Output("isLocalBackupEnabled")]
        public Output<bool> IsLocalBackupEnabled { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The Oracle license model that applies to the Autonomous VM cluster. The default is BRING_YOUR_OWN_LICENSE.
        /// </summary>
        [Output("licenseModel")]
        public Output<string> LicenseModel { get; private set; } = null!;

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The memory allocated in GBs.
        /// </summary>
        [Output("memorySizeInGbs")]
        public Output<int> MemorySizeInGbs { get; private set; } = null!;

        /// <summary>
        /// The current state of the Autonomous VM cluster.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time that the Autonomous VM cluster was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time zone to use for the Autonomous VM cluster. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
        /// </summary>
        [Output("timeZone")]
        public Output<string> TimeZone { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
        /// </summary>
        [Output("vmClusterNetworkId")]
        public Output<string> VmClusterNetworkId { get; private set; } = null!;


        /// <summary>
        /// Create a AutonomousVmCluster resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public AutonomousVmCluster(string name, AutonomousVmClusterArgs args, CustomResourceOptions? options = null)
            : base("oci:database/autonomousVmCluster:AutonomousVmCluster", name, args ?? new AutonomousVmClusterArgs(), MakeResourceOptions(options, ""))
        {
        }

        private AutonomousVmCluster(string name, Input<string> id, AutonomousVmClusterState? state = null, CustomResourceOptions? options = null)
            : base("oci:database/autonomousVmCluster:AutonomousVmCluster", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing AutonomousVmCluster resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static AutonomousVmCluster Get(string name, Input<string> id, AutonomousVmClusterState? state = null, CustomResourceOptions? options = null)
        {
            return new AutonomousVmCluster(name, id, state, options);
        }
    }

    public sealed class AutonomousVmClusterArgs : Pulumi.ResourceArgs
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
        /// The user-friendly name for the Autonomous VM cluster. The name does not need to be unique.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
        /// </summary>
        [Input("exadataInfrastructureId", required: true)]
        public Input<string> ExadataInfrastructureId { get; set; } = null!;

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
        /// If true, database backup on local Exadata storage is configured for the Autonomous VM cluster. If false, database backup on local Exadata storage is not available in the Autonomous VM cluster.
        /// </summary>
        [Input("isLocalBackupEnabled")]
        public Input<bool>? IsLocalBackupEnabled { get; set; }

        /// <summary>
        /// (Updatable) The Oracle license model that applies to the Autonomous VM cluster. The default is BRING_YOUR_OWN_LICENSE.
        /// </summary>
        [Input("licenseModel")]
        public Input<string>? LicenseModel { get; set; }

        /// <summary>
        /// The time zone to use for the Autonomous VM cluster. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
        /// </summary>
        [Input("timeZone")]
        public Input<string>? TimeZone { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
        /// </summary>
        [Input("vmClusterNetworkId", required: true)]
        public Input<string> VmClusterNetworkId { get; set; } = null!;

        public AutonomousVmClusterArgs()
        {
        }
    }

    public sealed class AutonomousVmClusterState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The numnber of CPU cores available.
        /// </summary>
        [Input("availableCpus")]
        public Input<int>? AvailableCpus { get; set; }

        /// <summary>
        /// The data storage available in TBs
        /// </summary>
        [Input("availableDataStorageSizeInTbs")]
        public Input<double>? AvailableDataStorageSizeInTbs { get; set; }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The number of enabled CPU cores.
        /// </summary>
        [Input("cpusEnabled")]
        public Input<int>? CpusEnabled { get; set; }

        /// <summary>
        /// The total data storage allocated in TBs
        /// </summary>
        [Input("dataStorageSizeInTbs")]
        public Input<double>? DataStorageSizeInTbs { get; set; }

        /// <summary>
        /// The local node storage allocated in GBs.
        /// </summary>
        [Input("dbNodeStorageSizeInGbs")]
        public Input<int>? DbNodeStorageSizeInGbs { get; set; }

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
        /// The user-friendly name for the Autonomous VM cluster. The name does not need to be unique.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
        /// </summary>
        [Input("exadataInfrastructureId")]
        public Input<string>? ExadataInfrastructureId { get; set; }

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
        /// If true, database backup on local Exadata storage is configured for the Autonomous VM cluster. If false, database backup on local Exadata storage is not available in the Autonomous VM cluster.
        /// </summary>
        [Input("isLocalBackupEnabled")]
        public Input<bool>? IsLocalBackupEnabled { get; set; }

        /// <summary>
        /// (Updatable) The Oracle license model that applies to the Autonomous VM cluster. The default is BRING_YOUR_OWN_LICENSE.
        /// </summary>
        [Input("licenseModel")]
        public Input<string>? LicenseModel { get; set; }

        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The memory allocated in GBs.
        /// </summary>
        [Input("memorySizeInGbs")]
        public Input<int>? MemorySizeInGbs { get; set; }

        /// <summary>
        /// The current state of the Autonomous VM cluster.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time that the Autonomous VM cluster was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time zone to use for the Autonomous VM cluster. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
        /// </summary>
        [Input("timeZone")]
        public Input<string>? TimeZone { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
        /// </summary>
        [Input("vmClusterNetworkId")]
        public Input<string>? VmClusterNetworkId { get; set; }

        public AutonomousVmClusterState()
        {
        }
    }
}
