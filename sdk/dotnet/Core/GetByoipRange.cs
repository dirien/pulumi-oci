// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetByoipRange
    {
        /// <summary>
        /// This data source provides details about a specific Byoip Range resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the `ByoipRange` resource. You must specify the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testByoipRange = Output.Create(Oci.Core.GetByoipRange.InvokeAsync(new Oci.Core.GetByoipRangeArgs
        ///         {
        ///             ByoipRangeId = oci_core_byoip_range.Test_byoip_range.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetByoipRangeResult> InvokeAsync(GetByoipRangeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetByoipRangeResult>("oci:core/getByoipRange:getByoipRange", args ?? new GetByoipRangeArgs(), options.WithVersion());
    }


    public sealed class GetByoipRangeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `ByoipRange` resource containing the BYOIP CIDR block.
        /// </summary>
        [Input("byoipRangeId", required: true)]
        public string ByoipRangeId { get; set; } = null!;

        public GetByoipRangeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetByoipRangeResult
    {
        public readonly string ByoipRangeId;
        /// <summary>
        /// The public IPv4 CIDR block being imported from on-premises to the Oracle cloud.
        /// </summary>
        public readonly string CidrBlock;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the BYOIP CIDR block.
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
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The `ByoipRange` resource's current status.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The `ByoipRange` resource's current state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the `ByoipRange` resource was advertised to the internet by BGP, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeAdvertised;
        /// <summary>
        /// The date and time the `ByoipRange` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the `ByoipRange` resource was validated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeValidated;
        /// <summary>
        /// The date and time the `ByoipRange` resource was withdrawn from advertisement by BGP to the internet, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeWithdrawn;
        /// <summary>
        /// The validation token is an internally-generated ASCII string used in the validation process. See [Importing a CIDR block](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/BYOIP.htm#import_cidr) for details.
        /// </summary>
        public readonly string ValidationToken;

        [OutputConstructor]
        private GetByoipRangeResult(
            string byoipRangeId,

            string cidrBlock,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            string state,

            string timeAdvertised,

            string timeCreated,

            string timeValidated,

            string timeWithdrawn,

            string validationToken)
        {
            ByoipRangeId = byoipRangeId;
            CidrBlock = cidrBlock;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            State = state;
            TimeAdvertised = timeAdvertised;
            TimeCreated = timeCreated;
            TimeValidated = timeValidated;
            TimeWithdrawn = timeWithdrawn;
            ValidationToken = validationToken;
        }
    }
}
