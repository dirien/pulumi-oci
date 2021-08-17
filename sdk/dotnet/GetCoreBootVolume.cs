// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    public static class GetCoreBootVolume
    {
        /// <summary>
        /// This data source provides details about a specific Boot Volume resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets information for the specified boot volume.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testBootVolume = Output.Create(Oci.GetCoreBootVolume.InvokeAsync(new Oci.GetCoreBootVolumeArgs
        ///         {
        ///             BootVolumeId = oci_core_boot_volume.Test_boot_volume.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetCoreBootVolumeResult> InvokeAsync(GetCoreBootVolumeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetCoreBootVolumeResult>("oci:index/getCoreBootVolume:GetCoreBootVolume", args ?? new GetCoreBootVolumeArgs(), options.WithVersion());
    }


    public sealed class GetCoreBootVolumeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the boot volume.
        /// </summary>
        [Input("bootVolumeId", required: true)]
        public string BootVolumeId { get; set; } = null!;

        public GetCoreBootVolumeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetCoreBootVolumeResult
    {
        /// <summary>
        /// The number of Volume Performance Units per GB that this boot volume is effectively tuned to when it's idle.
        /// </summary>
        public readonly string AutoTunedVpusPerGb;
        /// <summary>
        /// The availability domain of the boot volume replica.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        public readonly string BackupPolicyId;
        public readonly string BootVolumeId;
        /// <summary>
        /// The list of boot volume replicas of this boot volume
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCoreBootVolumeBootVolumeReplicaResult> BootVolumeReplicas;
        public readonly bool BootVolumeReplicasDeletion;
        /// <summary>
        /// The OCID of the compartment that contains the boot volume.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The OCID of the boot volume replica.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The image OCID used to create the boot volume.
        /// </summary>
        public readonly string ImageId;
        /// <summary>
        /// Specifies whether the auto-tune performance is enabled for this boot volume.
        /// </summary>
        public readonly bool IsAutoTuneEnabled;
        /// <summary>
        /// Specifies whether the boot volume's data has finished copying from the source boot volume or boot volume backup.
        /// </summary>
        public readonly bool IsHydrated;
        /// <summary>
        /// The OCID of the Key Management master encryption key assigned to the boot volume.
        /// </summary>
        public readonly string KmsKeyId;
        /// <summary>
        /// The size of the boot volume in GBs.
        /// </summary>
        public readonly string SizeInGbs;
        /// <summary>
        /// The size of the volume in MBs. The value must be a multiple of 1024. This field is deprecated. Please use `size_in_gbs`.
        /// </summary>
        public readonly string SizeInMbs;
        public readonly Outputs.GetCoreBootVolumeSourceDetailsResult SourceDetails;
        /// <summary>
        /// The current state of a boot volume.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The date and time the boot volume was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The OCID of the source volume group.
        /// </summary>
        public readonly string VolumeGroupId;
        /// <summary>
        /// The number of volume performance units (VPUs) that will be applied to this boot volume per GB, representing the Block Volume service's elastic performance options. See [Block Volume Elastic Performance](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeelasticperformance.htm) for more information.
        /// </summary>
        public readonly string VpusPerGb;

        [OutputConstructor]
        private GetCoreBootVolumeResult(
            string autoTunedVpusPerGb,

            string availabilityDomain,

            string backupPolicyId,

            string bootVolumeId,

            ImmutableArray<Outputs.GetCoreBootVolumeBootVolumeReplicaResult> bootVolumeReplicas,

            bool bootVolumeReplicasDeletion,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string imageId,

            bool isAutoTuneEnabled,

            bool isHydrated,

            string kmsKeyId,

            string sizeInGbs,

            string sizeInMbs,

            Outputs.GetCoreBootVolumeSourceDetailsResult sourceDetails,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string volumeGroupId,

            string vpusPerGb)
        {
            AutoTunedVpusPerGb = autoTunedVpusPerGb;
            AvailabilityDomain = availabilityDomain;
            BackupPolicyId = backupPolicyId;
            BootVolumeId = bootVolumeId;
            BootVolumeReplicas = bootVolumeReplicas;
            BootVolumeReplicasDeletion = bootVolumeReplicasDeletion;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            ImageId = imageId;
            IsAutoTuneEnabled = isAutoTuneEnabled;
            IsHydrated = isHydrated;
            KmsKeyId = kmsKeyId;
            SizeInGbs = sizeInGbs;
            SizeInMbs = sizeInMbs;
            SourceDetails = sourceDetails;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            VolumeGroupId = volumeGroupId;
            VpusPerGb = vpusPerGb;
        }
    }
}