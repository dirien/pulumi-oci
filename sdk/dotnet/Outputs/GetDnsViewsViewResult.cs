// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Outputs
{

    [OutputType]
    public sealed class GetDnsViewsViewResult
    {
        /// <summary>
        /// The OCID of the compartment the resource belongs to.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The displayName of a resource.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The OCID of a resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
        /// </summary>
        public readonly bool IsProtected;
        /// <summary>
        /// Value must be `PRIVATE` when listing private views.
        /// </summary>
        public readonly string Scope;
        /// <summary>
        /// The canonical absolute URL of the resource.
        /// </summary>
        public readonly string Self;
        /// <summary>
        /// The state of a resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDnsViewsViewResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            bool isProtected,

            string scope,

            string self,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IsProtected = isProtected;
            Scope = scope;
            Self = self;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}