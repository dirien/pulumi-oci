// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetDataSafePrivateEndpoints
    {
        /// <summary>
        /// This data source provides the list of Data Safe Private Endpoints in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of Data Safe private endpoints.
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
        ///         var testDataSafePrivateEndpoints = Output.Create(Oci.DataSafe.GetDataSafePrivateEndpoints.InvokeAsync(new Oci.DataSafe.GetDataSafePrivateEndpointsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AccessLevel = @var.Data_safe_private_endpoint_access_level,
        ///             CompartmentIdInSubtree = @var.Data_safe_private_endpoint_compartment_id_in_subtree,
        ///             DisplayName = @var.Data_safe_private_endpoint_display_name,
        ///             State = @var.Data_safe_private_endpoint_state,
        ///             VcnId = oci_core_vcn.Test_vcn.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDataSafePrivateEndpointsResult> InvokeAsync(GetDataSafePrivateEndpointsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDataSafePrivateEndpointsResult>("oci:datasafe/getDataSafePrivateEndpoints:getDataSafePrivateEndpoints", args ?? new GetDataSafePrivateEndpointsArgs(), options.WithVersion());
    }


    public sealed class GetDataSafePrivateEndpointsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public string? AccessLevel { get; set; }

        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public bool? CompartmentIdInSubtree { get; set; }

        /// <summary>
        /// A filter to return only resources that match the specified display name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDataSafePrivateEndpointsFilterArgs>? _filters;
        public List<Inputs.GetDataSafePrivateEndpointsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDataSafePrivateEndpointsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the specified lifecycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// A filter to return only resources that match the specified VCN OCID.
        /// </summary>
        [Input("vcnId")]
        public string? VcnId { get; set; }

        public GetDataSafePrivateEndpointsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDataSafePrivateEndpointsResult
    {
        public readonly string? AccessLevel;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        /// <summary>
        /// The list of data_safe_private_endpoints.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataSafePrivateEndpointsDataSafePrivateEndpointResult> DataSafePrivateEndpoints;
        /// <summary>
        /// The display name of the private endpoint.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDataSafePrivateEndpointsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of the private endpoint.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The OCID of the VCN.
        /// </summary>
        public readonly string? VcnId;

        [OutputConstructor]
        private GetDataSafePrivateEndpointsResult(
            string? accessLevel,

            string compartmentId,

            bool? compartmentIdInSubtree,

            ImmutableArray<Outputs.GetDataSafePrivateEndpointsDataSafePrivateEndpointResult> dataSafePrivateEndpoints,

            string? displayName,

            ImmutableArray<Outputs.GetDataSafePrivateEndpointsFilterResult> filters,

            string id,

            string? state,

            string? vcnId)
        {
            AccessLevel = accessLevel;
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            DataSafePrivateEndpoints = dataSafePrivateEndpoints;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
            VcnId = vcnId;
        }
    }
}
