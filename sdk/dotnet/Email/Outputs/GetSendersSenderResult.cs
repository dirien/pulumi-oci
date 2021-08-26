// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Email.Outputs
{

    [OutputType]
    public sealed class GetSendersSenderResult
    {
        /// <summary>
        /// The OCID for the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The email address of the approved sender.
        /// </summary>
        public readonly string EmailAddress;
        /// <summary>
        /// The email domain used to assert responsibility for emails sent from this sender.
        /// </summary>
        public readonly string EmailDomainId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The unique OCID of the sender.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
        /// </summary>
        public readonly bool IsSpf;
        /// <summary>
        /// The current state of a sender.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the approved sender was added in "YYYY-MM-ddThh:mmZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetSendersSenderResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string emailAddress,

            string emailDomainId,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            bool isSpf,

            string state,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            EmailAddress = emailAddress;
            EmailDomainId = emailDomainId;
            FreeformTags = freeformTags;
            Id = id;
            IsSpf = isSpf;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}