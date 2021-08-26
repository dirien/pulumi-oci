// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    /// <summary>
    /// This resource provides the Instance Configuration resource in Oracle Cloud Infrastructure Core service.
    /// 
    /// Creates an instance configuration. An instance configuration is a template that defines the
    /// settings to use when creating Compute instances.
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
    ///         var testInstanceConfiguration = new Oci.Core.InstanceConfiguration("testInstanceConfiguration", new Oci.Core.InstanceConfigurationArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             DefinedTags = 
    ///             {
    ///                 { "Operations.CostCenter", "42" },
    ///             },
    ///             DisplayName = @var.Instance_configuration_display_name,
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///             InstanceDetails = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsArgs
    ///             {
    ///                 InstanceType = @var.Instance_configuration_instance_details_instance_type,
    ///                 BlockVolumes = 
    ///                 {
    ///                     new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsBlockVolumeArgs
    ///                     {
    ///                         AttachDetails = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsBlockVolumeAttachDetailsArgs
    ///                         {
    ///                             Type = @var.Instance_configuration_instance_details_block_volumes_attach_details_type,
    ///                             Device = @var.Instance_configuration_instance_details_block_volumes_attach_details_device,
    ///                             DisplayName = @var.Instance_configuration_instance_details_block_volumes_attach_details_display_name,
    ///                             IsPvEncryptionInTransitEnabled = @var.Instance_configuration_instance_details_block_volumes_attach_details_is_pv_encryption_in_transit_enabled,
    ///                             IsReadOnly = @var.Instance_configuration_instance_details_block_volumes_attach_details_is_read_only,
    ///                             IsShareable = @var.Instance_configuration_instance_details_block_volumes_attach_details_is_shareable,
    ///                             UseChap = @var.Instance_configuration_instance_details_block_volumes_attach_details_use_chap,
    ///                         },
    ///                         CreateDetails = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsArgs
    ///                         {
    ///                             AvailabilityDomain = @var.Instance_configuration_instance_details_block_volumes_create_details_availability_domain,
    ///                             BackupPolicyId = data.Oci_core_volume_backup_policies.Test_volume_backup_policies.Volume_backup_policies[0].Id,
    ///                             CompartmentId = @var.Compartment_id,
    ///                             DefinedTags = 
    ///                             {
    ///                                 { "Operations.CostCenter", "42" },
    ///                             },
    ///                             DisplayName = @var.Instance_configuration_instance_details_block_volumes_create_details_display_name,
    ///                             FreeformTags = 
    ///                             {
    ///                                 { "Department", "Finance" },
    ///                             },
    ///                             KmsKeyId = oci_kms_key.Test_key.Id,
    ///                             SizeInGbs = @var.Instance_configuration_instance_details_block_volumes_create_details_size_in_gbs,
    ///                             SourceDetails = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsSourceDetailsArgs
    ///                             {
    ///                                 Type = @var.Instance_configuration_instance_details_block_volumes_create_details_source_details_type,
    ///                                 Id = @var.Instance_configuration_instance_details_block_volumes_create_details_source_details_id,
    ///                             },
    ///                             VpusPerGb = @var.Instance_configuration_instance_details_block_volumes_create_details_vpus_per_gb,
    ///                         },
    ///                         VolumeId = oci_core_volume.Test_volume.Id,
    ///                     },
    ///                 },
    ///                 LaunchDetails = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsArgs
    ///                 {
    ///                     AgentConfig = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsAgentConfigArgs
    ///                     {
    ///                         AreAllPluginsDisabled = @var.Instance_configuration_instance_details_launch_details_agent_config_are_all_plugins_disabled,
    ///                         IsManagementDisabled = @var.Instance_configuration_instance_details_launch_details_agent_config_is_management_disabled,
    ///                         IsMonitoringDisabled = @var.Instance_configuration_instance_details_launch_details_agent_config_is_monitoring_disabled,
    ///                         PluginsConfigs = 
    ///                         {
    ///                             new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsAgentConfigPluginsConfigArgs
    ///                             {
    ///                                 DesiredState = @var.Instance_configuration_instance_details_launch_details_agent_config_plugins_config_desired_state,
    ///                                 Name = @var.Instance_configuration_instance_details_launch_details_agent_config_plugins_config_name,
    ///                             },
    ///                         },
    ///                     },
    ///                     AvailabilityConfig = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsAvailabilityConfigArgs
    ///                     {
    ///                         RecoveryAction = @var.Instance_configuration_instance_details_launch_details_availability_config_recovery_action,
    ///                     },
    ///                     AvailabilityDomain = @var.Instance_configuration_instance_details_launch_details_availability_domain,
    ///                     CapacityReservationId = oci_core_capacity_reservation.Test_capacity_reservation.Id,
    ///                     CompartmentId = @var.Compartment_id,
    ///                     CreateVnicDetails = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsCreateVnicDetailsArgs
    ///                     {
    ///                         AssignPrivateDnsRecord = @var.Instance_configuration_instance_details_launch_details_create_vnic_details_assign_private_dns_record,
    ///                         AssignPublicIp = @var.Instance_configuration_instance_details_launch_details_create_vnic_details_assign_public_ip,
    ///                         DefinedTags = 
    ///                         {
    ///                             { "Operations.CostCenter", "42" },
    ///                         },
    ///                         DisplayName = @var.Instance_configuration_instance_details_launch_details_create_vnic_details_display_name,
    ///                         FreeformTags = 
    ///                         {
    ///                             { "Department", "Finance" },
    ///                         },
    ///                         HostnameLabel = @var.Instance_configuration_instance_details_launch_details_create_vnic_details_hostname_label,
    ///                         NsgIds = @var.Instance_configuration_instance_details_launch_details_create_vnic_details_nsg_ids,
    ///                         PrivateIp = @var.Instance_configuration_instance_details_launch_details_create_vnic_details_private_ip,
    ///                         SkipSourceDestCheck = @var.Instance_configuration_instance_details_launch_details_create_vnic_details_skip_source_dest_check,
    ///                         SubnetId = oci_core_subnet.Test_subnet.Id,
    ///                     },
    ///                     DedicatedVmHostId = oci_core_dedicated_vm_host.Test_dedicated_vm_host.Id,
    ///                     DefinedTags = 
    ///                     {
    ///                         { "Operations.CostCenter", "42" },
    ///                     },
    ///                     DisplayName = @var.Instance_configuration_instance_details_launch_details_display_name,
    ///                     ExtendedMetadata = @var.Instance_configuration_instance_details_launch_details_extended_metadata,
    ///                     FaultDomain = @var.Instance_configuration_instance_details_launch_details_fault_domain,
    ///                     FreeformTags = 
    ///                     {
    ///                         { "Department", "Finance" },
    ///                     },
    ///                     InstanceOptions = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsInstanceOptionsArgs
    ///                     {
    ///                         AreLegacyImdsEndpointsDisabled = @var.Instance_configuration_instance_details_launch_details_instance_options_are_legacy_imds_endpoints_disabled,
    ///                     },
    ///                     IpxeScript = @var.Instance_configuration_instance_details_launch_details_ipxe_script,
    ///                     IsPvEncryptionInTransitEnabled = @var.Instance_configuration_instance_details_launch_details_is_pv_encryption_in_transit_enabled,
    ///                     LaunchMode = @var.Instance_configuration_instance_details_launch_details_launch_mode,
    ///                     LaunchOptions = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsLaunchOptionsArgs
    ///                     {
    ///                         BootVolumeType = @var.Instance_configuration_instance_details_launch_details_launch_options_boot_volume_type,
    ///                         Firmware = @var.Instance_configuration_instance_details_launch_details_launch_options_firmware,
    ///                         IsConsistentVolumeNamingEnabled = @var.Instance_configuration_instance_details_launch_details_launch_options_is_consistent_volume_naming_enabled,
    ///                         IsPvEncryptionInTransitEnabled = @var.Instance_configuration_instance_details_launch_details_launch_options_is_pv_encryption_in_transit_enabled,
    ///                         NetworkType = @var.Instance_configuration_instance_details_launch_details_launch_options_network_type,
    ///                         RemoteDataVolumeType = @var.Instance_configuration_instance_details_launch_details_launch_options_remote_data_volume_type,
    ///                     },
    ///                     Metadata = @var.Instance_configuration_instance_details_launch_details_metadata,
    ///                     PlatformConfig = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsPlatformConfigArgs
    ///                     {
    ///                         Type = @var.Instance_configuration_instance_details_launch_details_platform_config_type,
    ///                         NumaNodesPerSocket = @var.Instance_configuration_instance_details_launch_details_platform_config_numa_nodes_per_socket,
    ///                     },
    ///                     PreemptibleInstanceConfig = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsPreemptibleInstanceConfigArgs
    ///                     {
    ///                         PreemptionAction = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsPreemptibleInstanceConfigPreemptionActionArgs
    ///                         {
    ///                             Type = @var.Instance_configuration_instance_details_launch_details_preemptible_instance_config_preemption_action_type,
    ///                             PreserveBootVolume = @var.Instance_configuration_instance_details_launch_details_preemptible_instance_config_preemption_action_preserve_boot_volume,
    ///                         },
    ///                     },
    ///                     PreferredMaintenanceAction = @var.Instance_configuration_instance_details_launch_details_preferred_maintenance_action,
    ///                     Shape = @var.Instance_configuration_instance_details_launch_details_shape,
    ///                     ShapeConfig = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsShapeConfigArgs
    ///                     {
    ///                         BaselineOcpuUtilization = @var.Instance_configuration_instance_details_launch_details_shape_config_baseline_ocpu_utilization,
    ///                         MemoryInGbs = @var.Instance_configuration_instance_details_launch_details_shape_config_memory_in_gbs,
    ///                         Ocpus = @var.Instance_configuration_instance_details_launch_details_shape_config_ocpus,
    ///                     },
    ///                     SourceDetails = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsLaunchDetailsSourceDetailsArgs
    ///                     {
    ///                         SourceType = @var.Instance_configuration_instance_details_launch_details_source_details_source_type,
    ///                         BootVolumeId = oci_core_boot_volume.Test_boot_volume.Id,
    ///                         BootVolumeSizeInGbs = @var.Instance_configuration_instance_details_launch_details_source_details_boot_volume_size_in_gbs,
    ///                         ImageId = oci_core_image.Test_image.Id,
    ///                     },
    ///                 },
    ///                 SecondaryVnics = 
    ///                 {
    ///                     new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsSecondaryVnicArgs
    ///                     {
    ///                         CreateVnicDetails = new Oci.Core.Inputs.InstanceConfigurationInstanceDetailsSecondaryVnicCreateVnicDetailsArgs
    ///                         {
    ///                             AssignPrivateDnsRecord = @var.Instance_configuration_instance_details_secondary_vnics_create_vnic_details_assign_private_dns_record,
    ///                             AssignPublicIp = @var.Instance_configuration_instance_details_secondary_vnics_create_vnic_details_assign_public_ip,
    ///                             DefinedTags = 
    ///                             {
    ///                                 { "Operations.CostCenter", "42" },
    ///                             },
    ///                             DisplayName = @var.Instance_configuration_instance_details_secondary_vnics_create_vnic_details_display_name,
    ///                             FreeformTags = 
    ///                             {
    ///                                 { "Department", "Finance" },
    ///                             },
    ///                             HostnameLabel = @var.Instance_configuration_instance_details_secondary_vnics_create_vnic_details_hostname_label,
    ///                             NsgIds = @var.Instance_configuration_instance_details_secondary_vnics_create_vnic_details_nsg_ids,
    ///                             PrivateIp = @var.Instance_configuration_instance_details_secondary_vnics_create_vnic_details_private_ip,
    ///                             SkipSourceDestCheck = @var.Instance_configuration_instance_details_secondary_vnics_create_vnic_details_skip_source_dest_check,
    ///                             SubnetId = oci_core_subnet.Test_subnet.Id,
    ///                         },
    ///                         DisplayName = @var.Instance_configuration_instance_details_secondary_vnics_display_name,
    ///                         NicIndex = @var.Instance_configuration_instance_details_secondary_vnics_nic_index,
    ///                     },
    ///                 },
    ///             },
    ///             InstanceId = oci_core_instance.Test_instance.Id,
    ///             Source = @var.Instance_configuration_source,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// InstanceConfigurations can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:core/instanceConfiguration:InstanceConfiguration test_instance_configuration "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:core/instanceConfiguration:InstanceConfiguration")]
    public partial class InstanceConfiguration : Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// Parameters that were not specified when the instance configuration was created, but that are required to launch an instance from the instance configuration. See the [LaunchInstanceConfiguration](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance/LaunchInstanceConfiguration) operation.
        /// </summary>
        [Output("deferredFields")]
        public Output<ImmutableArray<string>> DeferredFields { get; private set; } = null!;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        [Output("instanceDetails")]
        public Output<Outputs.InstanceConfigurationInstanceDetails> InstanceDetails { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance to use to create the instance configuration.
        /// </summary>
        [Output("instanceId")]
        public Output<string> InstanceId { get; private set; } = null!;

        /// <summary>
        /// The source of the instance configuration. An instance configuration defines the settings to use when creating Compute instances, including details such as the base image, shape, and metadata. You can also specify the associated resources for the instance, such as block volume attachments and network configuration.
        /// </summary>
        [Output("source")]
        public Output<string> Source { get; private set; } = null!;

        /// <summary>
        /// The date and time the instance configuration was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;


        /// <summary>
        /// Create a InstanceConfiguration resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public InstanceConfiguration(string name, InstanceConfigurationArgs args, CustomResourceOptions? options = null)
            : base("oci:core/instanceConfiguration:InstanceConfiguration", name, args ?? new InstanceConfigurationArgs(), MakeResourceOptions(options, ""))
        {
        }

        private InstanceConfiguration(string name, Input<string> id, InstanceConfigurationState? state = null, CustomResourceOptions? options = null)
            : base("oci:core/instanceConfiguration:InstanceConfiguration", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing InstanceConfiguration resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static InstanceConfiguration Get(string name, Input<string> id, InstanceConfigurationState? state = null, CustomResourceOptions? options = null)
        {
            return new InstanceConfiguration(name, id, state, options);
        }
    }

    public sealed class InstanceConfigurationArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

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

        [Input("instanceDetails")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsArgs>? InstanceDetails { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance to use to create the instance configuration.
        /// </summary>
        [Input("instanceId")]
        public Input<string>? InstanceId { get; set; }

        /// <summary>
        /// The source of the instance configuration. An instance configuration defines the settings to use when creating Compute instances, including details such as the base image, shape, and metadata. You can also specify the associated resources for the instance, such as block volume attachments and network configuration.
        /// </summary>
        [Input("source")]
        public Input<string>? Source { get; set; }

        public InstanceConfigurationArgs()
        {
        }
    }

    public sealed class InstanceConfigurationState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("deferredFields")]
        private InputList<string>? _deferredFields;

        /// <summary>
        /// Parameters that were not specified when the instance configuration was created, but that are required to launch an instance from the instance configuration. See the [LaunchInstanceConfiguration](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance/LaunchInstanceConfiguration) operation.
        /// </summary>
        public InputList<string> DeferredFields
        {
            get => _deferredFields ?? (_deferredFields = new InputList<string>());
            set => _deferredFields = value;
        }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

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

        [Input("instanceDetails")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsGetArgs>? InstanceDetails { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance to use to create the instance configuration.
        /// </summary>
        [Input("instanceId")]
        public Input<string>? InstanceId { get; set; }

        /// <summary>
        /// The source of the instance configuration. An instance configuration defines the settings to use when creating Compute instances, including details such as the base image, shape, and metadata. You can also specify the associated resources for the instance, such as block volume attachments and network configuration.
        /// </summary>
        [Input("source")]
        public Input<string>? Source { get; set; }

        /// <summary>
        /// The date and time the instance configuration was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        public InstanceConfigurationState()
        {
        }
    }
}
