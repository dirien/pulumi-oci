// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetBootVolumesBootVolumeResult
    {
        /// <summary>
        /// The number of Volume Performance Units per GB that this boot volume is effectively tuned to when it's idle.
        /// </summary>
        public readonly string AutoTunedVpusPerGb;
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        public readonly string BackupPolicyId;
        /// <summary>
        /// The list of boot volume replicas of this boot volume
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBootVolumesBootVolumeBootVolumeReplicaResult> BootVolumeReplicas;
        public readonly bool BootVolumeReplicasDeletion;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
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
        public readonly Outputs.GetBootVolumesBootVolumeSourceDetailsResult SourceDetails;
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
        /// The OCID of the volume group.
        /// </summary>
        public readonly string VolumeGroupId;
        /// <summary>
        /// The number of volume performance units (VPUs) that will be applied to this boot volume per GB, representing the Block Volume service's elastic performance options. See [Block Volume Elastic Performance](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeelasticperformance.htm) for more information.
        /// </summary>
        public readonly string VpusPerGb;

        [OutputConstructor]
        private GetBootVolumesBootVolumeResult(
            string autoTunedVpusPerGb,

            string availabilityDomain,

            string backupPolicyId,

            ImmutableArray<Outputs.GetBootVolumesBootVolumeBootVolumeReplicaResult> bootVolumeReplicas,

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

            Outputs.GetBootVolumesBootVolumeSourceDetailsResult sourceDetails,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string volumeGroupId,

            string vpusPerGb)
        {
            AutoTunedVpusPerGb = autoTunedVpusPerGb;
            AvailabilityDomain = availabilityDomain;
            BackupPolicyId = backupPolicyId;
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
