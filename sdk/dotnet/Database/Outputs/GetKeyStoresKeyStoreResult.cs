// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetKeyStoresKeyStoreResult
    {
        /// <summary>
        /// List of databases associated with the key store.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetKeyStoresKeyStoreAssociatedDatabaseResult> AssociatedDatabases;
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The user-friendly name for the key store. The name does not need to be unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The current state of the key store.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time that the key store was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Key store type details.
        /// </summary>
        public readonly Outputs.GetKeyStoresKeyStoreTypeDetailsResult TypeDetails;

        [OutputConstructor]
        private GetKeyStoresKeyStoreResult(
            ImmutableArray<Outputs.GetKeyStoresKeyStoreAssociatedDatabaseResult> associatedDatabases,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            string state,

            string timeCreated,

            Outputs.GetKeyStoresKeyStoreTypeDetailsResult typeDetails)
        {
            AssociatedDatabases = associatedDatabases;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            State = state;
            TimeCreated = timeCreated;
            TypeDetails = typeDetails;
        }
    }
}
