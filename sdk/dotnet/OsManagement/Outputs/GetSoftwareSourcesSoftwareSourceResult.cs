// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagement.Outputs
{

    [OutputType]
    public sealed class GetSoftwareSourcesSoftwareSourceResult
    {
        /// <summary>
        /// The architecture type supported by the Software Source
        /// </summary>
        public readonly string ArchType;
        /// <summary>
        /// list of the Managed Instances associated with this Software Sources
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSoftwareSourcesSoftwareSourceAssociatedManagedInstanceResult> AssociatedManagedInstances;
        /// <summary>
        /// The yum repository checksum type used by this software source
        /// </summary>
        public readonly string ChecksumType;
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Information specified by the user about the software source
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Fingerprint of the GPG key for this software source
        /// </summary>
        public readonly string GpgKeyFingerprint;
        /// <summary>
        /// ID of the GPG key for this software source
        /// </summary>
        public readonly string GpgKeyId;
        /// <summary>
        /// URL of the GPG key for this software source
        /// </summary>
        public readonly string GpgKeyUrl;
        /// <summary>
        /// OCID for the Software Source
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Email address of the person maintaining this software source
        /// </summary>
        public readonly string MaintainerEmail;
        /// <summary>
        /// Name of the person maintaining this software source
        /// </summary>
        public readonly string MaintainerName;
        /// <summary>
        /// Phone number of the person maintaining this software source
        /// </summary>
        public readonly string MaintainerPhone;
        /// <summary>
        /// Number of packages
        /// </summary>
        public readonly int Packages;
        /// <summary>
        /// OCID for the parent software source, if there is one
        /// </summary>
        public readonly string ParentId;
        /// <summary>
        /// Display name the parent software source, if there is one
        /// </summary>
        public readonly string ParentName;
        /// <summary>
        /// Type of the Software Source
        /// </summary>
        public readonly string RepoType;
        /// <summary>
        /// The current lifecycle state for the object.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// status of the software source.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// URL for the repostiory
        /// </summary>
        public readonly string Url;

        [OutputConstructor]
        private GetSoftwareSourcesSoftwareSourceResult(
            string archType,

            ImmutableArray<Outputs.GetSoftwareSourcesSoftwareSourceAssociatedManagedInstanceResult> associatedManagedInstances,

            string checksumType,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string gpgKeyFingerprint,

            string gpgKeyId,

            string gpgKeyUrl,

            string id,

            string maintainerEmail,

            string maintainerName,

            string maintainerPhone,

            int packages,

            string parentId,

            string parentName,

            string repoType,

            string state,

            string status,

            string url)
        {
            ArchType = archType;
            AssociatedManagedInstances = associatedManagedInstances;
            ChecksumType = checksumType;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            GpgKeyFingerprint = gpgKeyFingerprint;
            GpgKeyId = gpgKeyId;
            GpgKeyUrl = gpgKeyUrl;
            Id = id;
            MaintainerEmail = maintainerEmail;
            MaintainerName = maintainerName;
            MaintainerPhone = maintainerPhone;
            Packages = packages;
            ParentId = parentId;
            ParentName = parentName;
            RepoType = repoType;
            State = state;
            Status = status;
            Url = url;
        }
    }
}
