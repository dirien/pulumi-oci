// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FileStorage.Outputs
{

    [OutputType]
    public sealed class GetSnapshotsSnapshotResult
    {
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
        /// </summary>
        public readonly string FileSystemId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Specifies whether the snapshot has been cloned. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
        /// </summary>
        public readonly bool IsCloneSource;
        /// <summary>
        /// Additional information about the current 'lifecycleState'.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Name of the snapshot. This value is immutable.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) identifying the parent from which this snapshot was cloned. If this snapshot was not cloned, then the `provenanceId` is the same as the snapshot `id` value. If this snapshot was cloned, then the `provenanceId` value is the parent's `provenanceId`. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
        /// </summary>
        public readonly string ProvenanceId;
        /// <summary>
        /// Filter results by the specified lifecycle state. Must be a valid state for the resource type.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the snapshot was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetSnapshotsSnapshotResult(
            ImmutableDictionary<string, object> definedTags,

            string fileSystemId,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            bool isCloneSource,

            string lifecycleDetails,

            string name,

            string provenanceId,

            string state,

            string timeCreated)
        {
            DefinedTags = definedTags;
            FileSystemId = fileSystemId;
            FreeformTags = freeformTags;
            Id = id;
            IsCloneSource = isCloneSource;
            LifecycleDetails = lifecycleDetails;
            Name = name;
            ProvenanceId = provenanceId;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}
