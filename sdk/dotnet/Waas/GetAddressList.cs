// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas
{
    public static class GetAddressList
    {
        /// <summary>
        /// This data source provides details about a specific Address List resource in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
        /// 
        /// Gets the details of an address list.
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
        ///         var testAddressList = Output.Create(Oci.Waas.GetAddressList.InvokeAsync(new Oci.Waas.GetAddressListArgs
        ///         {
        ///             AddressListId = oci_waas_address_list.Test_address_list.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAddressListResult> InvokeAsync(GetAddressListArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAddressListResult>("oci:waas/getAddressList:getAddressList", args ?? new GetAddressListArgs(), options.WithVersion());
    }


    public sealed class GetAddressListArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the address list. This number is generated when the address list is added to the compartment.
        /// </summary>
        [Input("addressListId", required: true)]
        public string AddressListId { get; set; } = null!;

        public GetAddressListArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetAddressListResult
    {
        /// <summary>
        /// The total number of unique IP addresses in the address list.
        /// </summary>
        public readonly double AddressCount;
        public readonly string AddressListId;
        /// <summary>
        /// The list of IP addresses or CIDR notations.
        /// </summary>
        public readonly ImmutableArray<string> Addresses;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the address list's compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The user-friendly name of the address list.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the address list.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current lifecycle state of the address list.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the address list was created, expressed in RFC 3339 timestamp format.
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetAddressListResult(
            double addressCount,

            string addressListId,

            ImmutableArray<string> addresses,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string state,

            string timeCreated)
        {
            AddressCount = addressCount;
            AddressListId = addressListId;
            Addresses = addresses;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}
