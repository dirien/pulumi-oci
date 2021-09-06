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
    public sealed class InstanceConfigurationInstanceDetailsBlockVolumeCreateDetails
    {
        /// <summary>
        /// The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string? AvailabilityDomain;
        /// <summary>
        /// If provided, specifies the ID of the volume backup policy to assign to the newly created volume. If omitted, no policy will be assigned.
        /// </summary>
        public readonly string? BackupPolicyId;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object>? DefinedTags;
        /// <summary>
        /// A user-friendly name for the attachment. Does not have to be unique, and it cannot be changed.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object>? FreeformTags;
        /// <summary>
        /// The OCID of the Key Management key to assign as the master encryption key for the volume.
        /// </summary>
        public readonly string? KmsKeyId;
        /// <summary>
        /// The size of the volume in GBs.
        /// </summary>
        public readonly string? SizeInGbs;
        public readonly Outputs.InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsSourceDetails? SourceDetails;
        /// <summary>
        /// The number of volume performance units (VPUs) that will be applied to this volume per GB, representing the Block Volume service's elastic performance options. See [Block Volume Elastic Performance](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumeelasticperformance.htm) for more information.
        /// </summary>
        public readonly string? VpusPerGb;

        [OutputConstructor]
        private InstanceConfigurationInstanceDetailsBlockVolumeCreateDetails(
            string? availabilityDomain,

            string? backupPolicyId,

            string? compartmentId,

            ImmutableDictionary<string, object>? definedTags,

            string? displayName,

            ImmutableDictionary<string, object>? freeformTags,

            string? kmsKeyId,

            string? sizeInGbs,

            Outputs.InstanceConfigurationInstanceDetailsBlockVolumeCreateDetailsSourceDetails? sourceDetails,

            string? vpusPerGb)
        {
            AvailabilityDomain = availabilityDomain;
            BackupPolicyId = backupPolicyId;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            KmsKeyId = kmsKeyId;
            SizeInGbs = sizeInGbs;
            SourceDetails = sourceDetails;
            VpusPerGb = vpusPerGb;
        }
    }
}
