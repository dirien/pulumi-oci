// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetOnPremConnectors
    {
        /// <summary>
        /// This data source provides the list of On Prem Connectors in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of on-premises connectors.
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
        ///         var testOnPremConnectors = Output.Create(Oci.DataSafe.GetOnPremConnectors.InvokeAsync(new Oci.DataSafe.GetOnPremConnectorsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AccessLevel = @var.On_prem_connector_access_level,
        ///             CompartmentIdInSubtree = @var.On_prem_connector_compartment_id_in_subtree,
        ///             DisplayName = @var.On_prem_connector_display_name,
        ///             OnPremConnectorId = oci_data_safe_on_prem_connector.Test_on_prem_connector.Id,
        ///             OnPremConnectorLifecycleState = @var.On_prem_connector_on_prem_connector_lifecycle_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetOnPremConnectorsResult> InvokeAsync(GetOnPremConnectorsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetOnPremConnectorsResult>("oci:datasafe/getOnPremConnectors:getOnPremConnectors", args ?? new GetOnPremConnectorsArgs(), options.WithVersion());
    }


    public sealed class GetOnPremConnectorsArgs : Pulumi.InvokeArgs
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
        private List<Inputs.GetOnPremConnectorsFilterArgs>? _filters;
        public List<Inputs.GetOnPremConnectorsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetOnPremConnectorsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only the on-premises connector that matches the specified id.
        /// </summary>
        [Input("onPremConnectorId")]
        public string? OnPremConnectorId { get; set; }

        /// <summary>
        /// A filter to return only on-premises connector resources that match the specified lifecycle state.
        /// </summary>
        [Input("onPremConnectorLifecycleState")]
        public string? OnPremConnectorLifecycleState { get; set; }

        public GetOnPremConnectorsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetOnPremConnectorsResult
    {
        public readonly string? AccessLevel;
        /// <summary>
        /// The OCID of the compartment that contains the on-premises connector.
        /// </summary>
        public readonly string CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        /// <summary>
        /// The display name of the on-premises connector.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetOnPremConnectorsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? OnPremConnectorId;
        public readonly string? OnPremConnectorLifecycleState;
        /// <summary>
        /// The list of on_prem_connectors.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOnPremConnectorsOnPremConnectorResult> OnPremConnectors;

        [OutputConstructor]
        private GetOnPremConnectorsResult(
            string? accessLevel,

            string compartmentId,

            bool? compartmentIdInSubtree,

            string? displayName,

            ImmutableArray<Outputs.GetOnPremConnectorsFilterResult> filters,

            string id,

            string? onPremConnectorId,

            string? onPremConnectorLifecycleState,

            ImmutableArray<Outputs.GetOnPremConnectorsOnPremConnectorResult> onPremConnectors)
        {
            AccessLevel = accessLevel;
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            OnPremConnectorId = onPremConnectorId;
            OnPremConnectorLifecycleState = onPremConnectorLifecycleState;
            OnPremConnectors = onPremConnectors;
        }
    }
}