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
    public sealed class GetVolumeGroupsVolumeGroupResult
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        public readonly string BackupPolicyId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The OCID for the volume group.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Specifies whether the newly created cloned volume group's data has finished copying from the source volume group or backup.
        /// </summary>
        public readonly bool IsHydrated;
        /// <summary>
        /// The aggregate size of the volume group in GBs.
        /// </summary>
        public readonly string SizeInGbs;
        /// <summary>
        /// The aggregate size of the volume group in MBs.
        /// </summary>
        public readonly string SizeInMbs;
        /// <summary>
        /// Specifies the source for a volume group.
        /// </summary>
        public readonly Outputs.GetVolumeGroupsVolumeGroupSourceDetailsResult SourceDetails;
        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the volume group was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// OCIDs for the volumes in this volume group.
        /// </summary>
        public readonly ImmutableArray<string> VolumeIds;

        [OutputConstructor]
        private GetVolumeGroupsVolumeGroupResult(
            string availabilityDomain,

            string backupPolicyId,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            bool isHydrated,

            string sizeInGbs,

            string sizeInMbs,

            Outputs.GetVolumeGroupsVolumeGroupSourceDetailsResult sourceDetails,

            string state,

            string timeCreated,

            ImmutableArray<string> volumeIds)
        {
            AvailabilityDomain = availabilityDomain;
            BackupPolicyId = backupPolicyId;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IsHydrated = isHydrated;
            SizeInGbs = sizeInGbs;
            SizeInMbs = sizeInMbs;
            SourceDetails = sourceDetails;
            State = state;
            TimeCreated = timeCreated;
            VolumeIds = volumeIds;
        }
    }
}
