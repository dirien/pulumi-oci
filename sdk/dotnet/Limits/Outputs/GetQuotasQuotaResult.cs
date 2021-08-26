// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Limits.Outputs
{

    [OutputType]
    public sealed class GetQuotasQuotaResult
    {
        /// <summary>
        /// The OCID of the parent compartment (remember that the tenancy is simply the root compartment).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The description you assign to the quota.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The OCID of the quota.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// name
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Filters returned quotas based on the given state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// An array of one or more quota statements written in the declarative quota statement language.
        /// </summary>
        public readonly ImmutableArray<string> Statements;
        /// <summary>
        /// Date and time the quota was created, in the format defined by RFC 3339. Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetQuotasQuotaResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string name,

            string state,

            ImmutableArray<string> statements,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            FreeformTags = freeformTags;
            Id = id;
            Name = name;
            State = state;
            Statements = statements;
            TimeCreated = timeCreated;
        }
    }
}
