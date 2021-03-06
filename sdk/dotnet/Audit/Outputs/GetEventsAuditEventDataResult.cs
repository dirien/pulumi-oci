// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Audit.Outputs
{

    [OutputType]
    public sealed class GetEventsAuditEventDataResult
    {
        /// <summary>
        /// A container object for attribues unique to the resource emitting the event.
        /// </summary>
        public readonly ImmutableDictionary<string, object> AdditionalDetails;
        /// <summary>
        /// The availability domain where the resource resides.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The name of the compartment. This value is the friendly name associated with compartmentId. This value can change, but the service logs the value that appeared at the time of the audit event.  Example: `CompartmentA`
        /// </summary>
        public readonly string CompartmentName;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// This value links multiple audit events that are part of the same API operation. For example,  a long running API operations that emit an event at the start and the end of an operation would use the same value in this field for both events.
        /// </summary>
        public readonly string EventGroupingId;
        /// <summary>
        /// Name of the API operation that generated this event.  Example: `GetInstance`
        /// </summary>
        public readonly string EventName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name,  type, or namespace. Exists for cross-compatibility only. For more information,  see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// A container object for identity attributes.
        /// </summary>
        public readonly Outputs.GetEventsAuditEventDataIdentityResult Identity;
        /// <summary>
        /// A container object for request attributes.
        /// </summary>
        public readonly Outputs.GetEventsAuditEventDataRequestResult Request;
        /// <summary>
        /// An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) or some other ID for the resource emitting the event.
        /// </summary>
        public readonly string ResourceId;
        /// <summary>
        /// The name of the resource emitting the event.
        /// </summary>
        public readonly string ResourceName;
        /// <summary>
        /// A container object for response attributes.
        /// </summary>
        public readonly Outputs.GetEventsAuditEventDataResponseResult Response;
        /// <summary>
        /// A container object for state change attributes.
        /// </summary>
        public readonly Outputs.GetEventsAuditEventDataStateChangeResult StateChange;

        [OutputConstructor]
        private GetEventsAuditEventDataResult(
            ImmutableDictionary<string, object> additionalDetails,

            string availabilityDomain,

            string compartmentId,

            string compartmentName,

            ImmutableDictionary<string, object> definedTags,

            string eventGroupingId,

            string eventName,

            ImmutableDictionary<string, object> freeformTags,

            Outputs.GetEventsAuditEventDataIdentityResult identity,

            Outputs.GetEventsAuditEventDataRequestResult request,

            string resourceId,

            string resourceName,

            Outputs.GetEventsAuditEventDataResponseResult response,

            Outputs.GetEventsAuditEventDataStateChangeResult stateChange)
        {
            AdditionalDetails = additionalDetails;
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            CompartmentName = compartmentName;
            DefinedTags = definedTags;
            EventGroupingId = eventGroupingId;
            EventName = eventName;
            FreeformTags = freeformTags;
            Identity = identity;
            Request = request;
            ResourceId = resourceId;
            ResourceName = resourceName;
            Response = response;
            StateChange = stateChange;
        }
    }
}
