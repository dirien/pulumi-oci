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
    /// This resource provides the Volume resource in Oracle Cloud Infrastructure Core service.
    /// 
    /// Creates a new volume in the specified compartment. Volumes can be created in sizes ranging from
    /// 50 GB (51200 MB) to 32 TB (33554432 MB), in 1 GB (1024 MB) increments. By default, volumes are 1 TB (1048576 MB).
    /// For general information about block volumes, see
    /// [Overview of Block Volume Service](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/overview.htm).
    /// 
    /// A volume and instance can be in separate compartments but must be in the same availability domain.
    /// For information about access control and compartments, see
    /// [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm). For information about
    /// availability domains, see [Regions and Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm).
    /// To get a list of availability domains, use the `ListAvailabilityDomains` operation
    /// in the Identity and Access Management Service API.
    /// 
    /// You may optionally specify a *display name* for the volume, which is simply a friendly name or
    /// description. It does not have to be unique, and you can change it. Avoid entering confidential information.
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
    ///         var testVolume = new Oci.Core.Volume("testVolume", new Oci.Core.VolumeArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             AvailabilityDomain = @var.Volume_availability_domain,
    ///             BackupPolicyId = data.Oci_core_volume_backup_policies.Test_volume_backup_policies.Volume_backup_policies[0].Id,
    ///             BlockVolumeReplicas = 
    ///             {
    ///                 new Oci.Core.Inputs.VolumeBlockVolumeReplicaArgs
    ///                 {
    ///                     AvailabilityDomain = @var.Volume_block_volume_replicas_availability_domain,
    ///                     DisplayName = @var.Volume_block_volume_replicas_display_name,
    ///                 },
    ///             },
    ///             DefinedTags = 
    ///             {
    ///                 { "Operations.CostCenter", "42" },
    ///             },
    ///             DisplayName = @var.Volume_display_name,
    ///             FreeformTags = 
    ///             {
    ///                 { "Department", "Finance" },
    ///             },
    ///             IsAutoTuneEnabled = @var.Volume_is_auto_tune_enabled,
    ///             KmsKeyId = oci_kms_key.Test_key.Id,
    ///             SizeInGbs = @var.Volume_size_in_gbs,
    ///             SizeInMbs = @var.Volume_size_in_mbs,
    ///             SourceDetails = new Oci.Core.Inputs.VolumeSourceDetailsArgs
    ///             {
    ///                 Id = @var.Volume_source_details_id,
    ///                 Type = @var.Volume_source_details_type,
    ///             },
    ///             VpusPerGb = @var.Volume_vpus_per_gb,
    ///             BlockVolumeReplicasDeletion = true,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Volumes can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:core/volume:Volume test_volume "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:core/volume:Volume")]
    public partial class Volume : Pulumi.CustomResource
    {
        /// <summary>
        /// The number of Volume Performance Units per GB that this volume is effectively tuned to when it's idle.
        /// </summary>
        [Output("autoTunedVpusPerGb")]
        public Output<string> AutoTunedVpusPerGb { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The availability domain of the block volume replica.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Output("availabilityDomain")]
        public Output<string> AvailabilityDomain { get; private set; } = null!;

        /// <summary>
        /// If provided, specifies the ID of the volume backup policy to assign to the newly created volume. If omitted, no policy will be assigned.
        /// </summary>
        [Output("backupPolicyId")]
        public Output<string> BackupPolicyId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The list of block volume replicas to be enabled for this volume in the specified destination availability domains.
        /// </summary>
        [Output("blockVolumeReplicas")]
        public Output<ImmutableArray<Outputs.VolumeBlockVolumeReplica>> BlockVolumeReplicas { get; private set; } = null!;

        /// <summary>
        /// (updatable) The boolean value, if you have replicas and want to disable replicas set this argument to true and remove `block_volume_replicas` in representation at the same time. If you want to enable a new replicas, remove this argument and use `block_volume_replicas` again.
        /// </summary>
        [Output("blockVolumeReplicasDeletion")]
        public Output<bool?> BlockVolumeReplicasDeletion { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the compartment that contains the volume.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Specifies whether the auto-tune performance is enabled for this volume.
        /// </summary>
        [Output("isAutoTuneEnabled")]
        public Output<bool> IsAutoTuneEnabled { get; private set; } = null!;

        /// <summary>
        /// Specifies whether the cloned volume's data has finished copying from the source volume or backup.
        /// </summary>
        [Output("isHydrated")]
        public Output<bool> IsHydrated { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the Key Management key to assign as the master encryption key for the volume.
        /// </summary>
        [Output("kmsKeyId")]
        public Output<string> KmsKeyId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The size of the volume in GBs.
        /// </summary>
        [Output("sizeInGbs")]
        public Output<string> SizeInGbs { get; private set; } = null!;

        /// <summary>
        /// The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Use `size_in_gbs` instead.
        /// </summary>
        [Output("sizeInMbs")]
        public Output<string> SizeInMbs { get; private set; } = null!;

        [Output("sourceDetails")]
        public Output<Outputs.VolumeSourceDetails> SourceDetails { get; private set; } = null!;

        /// <summary>
        /// The current state of a volume.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time the volume was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The OCID of the volume backup from which the data should be restored on the newly created volume. This field is deprecated. Use the `source_details` field instead to specify the backup for the volume.
        /// </summary>
        [Output("volumeBackupId")]
        public Output<string> VolumeBackupId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the source volume group.
        /// </summary>
        [Output("volumeGroupId")]
        public Output<string> VolumeGroupId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service's elastic performance options. See [Block Volume Elastic Performance](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeelasticperformance.htm) for more information.
        /// </summary>
        [Output("vpusPerGb")]
        public Output<string> VpusPerGb { get; private set; } = null!;


        /// <summary>
        /// Create a Volume resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Volume(string name, VolumeArgs args, CustomResourceOptions? options = null)
            : base("oci:core/volume:Volume", name, args ?? new VolumeArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Volume(string name, Input<string> id, VolumeState? state = null, CustomResourceOptions? options = null)
            : base("oci:core/volume:Volume", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Volume resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Volume Get(string name, Input<string> id, VolumeState? state = null, CustomResourceOptions? options = null)
        {
            return new Volume(name, id, state, options);
        }
    }

    public sealed class VolumeArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The availability domain of the block volume replica.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain", required: true)]
        public Input<string> AvailabilityDomain { get; set; } = null!;

        /// <summary>
        /// If provided, specifies the ID of the volume backup policy to assign to the newly created volume. If omitted, no policy will be assigned.
        /// </summary>
        [Input("backupPolicyId")]
        public Input<string>? BackupPolicyId { get; set; }

        [Input("blockVolumeReplicas")]
        private InputList<Inputs.VolumeBlockVolumeReplicaArgs>? _blockVolumeReplicas;

        /// <summary>
        /// (Updatable) The list of block volume replicas to be enabled for this volume in the specified destination availability domains.
        /// </summary>
        public InputList<Inputs.VolumeBlockVolumeReplicaArgs> BlockVolumeReplicas
        {
            get => _blockVolumeReplicas ?? (_blockVolumeReplicas = new InputList<Inputs.VolumeBlockVolumeReplicaArgs>());
            set => _blockVolumeReplicas = value;
        }

        /// <summary>
        /// (updatable) The boolean value, if you have replicas and want to disable replicas set this argument to true and remove `block_volume_replicas` in representation at the same time. If you want to enable a new replicas, remove this argument and use `block_volume_replicas` again.
        /// </summary>
        [Input("blockVolumeReplicasDeletion")]
        public Input<bool>? BlockVolumeReplicasDeletion { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the compartment that contains the volume.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
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
        /// (Updatable) Specifies whether the auto-tune performance is enabled for this volume.
        /// </summary>
        [Input("isAutoTuneEnabled")]
        public Input<bool>? IsAutoTuneEnabled { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the Key Management key to assign as the master encryption key for the volume.
        /// </summary>
        [Input("kmsKeyId")]
        public Input<string>? KmsKeyId { get; set; }

        /// <summary>
        /// (Updatable) The size of the volume in GBs.
        /// </summary>
        [Input("sizeInGbs")]
        public Input<string>? SizeInGbs { get; set; }

        /// <summary>
        /// The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Use `size_in_gbs` instead.
        /// </summary>
        [Input("sizeInMbs")]
        public Input<string>? SizeInMbs { get; set; }

        [Input("sourceDetails")]
        public Input<Inputs.VolumeSourceDetailsArgs>? SourceDetails { get; set; }

        /// <summary>
        /// The OCID of the volume backup from which the data should be restored on the newly created volume. This field is deprecated. Use the `source_details` field instead to specify the backup for the volume.
        /// </summary>
        [Input("volumeBackupId")]
        public Input<string>? VolumeBackupId { get; set; }

        /// <summary>
        /// (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service's elastic performance options. See [Block Volume Elastic Performance](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeelasticperformance.htm) for more information.
        /// </summary>
        [Input("vpusPerGb")]
        public Input<string>? VpusPerGb { get; set; }

        public VolumeArgs()
        {
        }
    }

    public sealed class VolumeState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The number of Volume Performance Units per GB that this volume is effectively tuned to when it's idle.
        /// </summary>
        [Input("autoTunedVpusPerGb")]
        public Input<string>? AutoTunedVpusPerGb { get; set; }

        /// <summary>
        /// (Updatable) The availability domain of the block volume replica.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// If provided, specifies the ID of the volume backup policy to assign to the newly created volume. If omitted, no policy will be assigned.
        /// </summary>
        [Input("backupPolicyId")]
        public Input<string>? BackupPolicyId { get; set; }

        [Input("blockVolumeReplicas")]
        private InputList<Inputs.VolumeBlockVolumeReplicaGetArgs>? _blockVolumeReplicas;

        /// <summary>
        /// (Updatable) The list of block volume replicas to be enabled for this volume in the specified destination availability domains.
        /// </summary>
        public InputList<Inputs.VolumeBlockVolumeReplicaGetArgs> BlockVolumeReplicas
        {
            get => _blockVolumeReplicas ?? (_blockVolumeReplicas = new InputList<Inputs.VolumeBlockVolumeReplicaGetArgs>());
            set => _blockVolumeReplicas = value;
        }

        /// <summary>
        /// (updatable) The boolean value, if you have replicas and want to disable replicas set this argument to true and remove `block_volume_replicas` in representation at the same time. If you want to enable a new replicas, remove this argument and use `block_volume_replicas` again.
        /// </summary>
        [Input("blockVolumeReplicasDeletion")]
        public Input<bool>? BlockVolumeReplicasDeletion { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the compartment that contains the volume.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
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
        /// (Updatable) Specifies whether the auto-tune performance is enabled for this volume.
        /// </summary>
        [Input("isAutoTuneEnabled")]
        public Input<bool>? IsAutoTuneEnabled { get; set; }

        /// <summary>
        /// Specifies whether the cloned volume's data has finished copying from the source volume or backup.
        /// </summary>
        [Input("isHydrated")]
        public Input<bool>? IsHydrated { get; set; }

        /// <summary>
        /// (Updatable) The OCID of the Key Management key to assign as the master encryption key for the volume.
        /// </summary>
        [Input("kmsKeyId")]
        public Input<string>? KmsKeyId { get; set; }

        /// <summary>
        /// (Updatable) The size of the volume in GBs.
        /// </summary>
        [Input("sizeInGbs")]
        public Input<string>? SizeInGbs { get; set; }

        /// <summary>
        /// The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Use `size_in_gbs` instead.
        /// </summary>
        [Input("sizeInMbs")]
        public Input<string>? SizeInMbs { get; set; }

        [Input("sourceDetails")]
        public Input<Inputs.VolumeSourceDetailsGetArgs>? SourceDetails { get; set; }

        /// <summary>
        /// The current state of a volume.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<object>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<object>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The date and time the volume was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The OCID of the volume backup from which the data should be restored on the newly created volume. This field is deprecated. Use the `source_details` field instead to specify the backup for the volume.
        /// </summary>
        [Input("volumeBackupId")]
        public Input<string>? VolumeBackupId { get; set; }

        /// <summary>
        /// The OCID of the source volume group.
        /// </summary>
        [Input("volumeGroupId")]
        public Input<string>? VolumeGroupId { get; set; }

        /// <summary>
        /// (Updatable) The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service's elastic performance options. See [Block Volume Elastic Performance](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeelasticperformance.htm) for more information.
        /// </summary>
        [Input("vpusPerGb")]
        public Input<string>? VpusPerGb { get; set; }

        public VolumeState()
        {
        }
    }
}
