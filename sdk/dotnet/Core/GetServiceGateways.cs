// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetServiceGateways
    {
        /// <summary>
        /// This data source provides the list of Service Gateways in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the service gateways in the specified compartment. You may optionally specify a VCN OCID
        /// to filter the results by VCN.
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
        ///         var testServiceGateways = Output.Create(Oci.Core.GetServiceGateways.InvokeAsync(new Oci.Core.GetServiceGatewaysArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             State = @var.Service_gateway_state,
        ///             VcnId = oci_core_vcn.Test_vcn.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetServiceGatewaysResult> InvokeAsync(GetServiceGatewaysArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetServiceGatewaysResult>("oci:core/getServiceGateways:getServiceGateways", args ?? new GetServiceGatewaysArgs(), options.WithVersion());
    }


    public sealed class GetServiceGatewaysArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetServiceGatewaysFilterArgs>? _filters;
        public List<Inputs.GetServiceGatewaysFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetServiceGatewaysFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        /// </summary>
        [Input("vcnId")]
        public string? VcnId { get; set; }

        public GetServiceGatewaysArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetServiceGatewaysResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the service gateway.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetServiceGatewaysFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of service_gateways.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetServiceGatewaysServiceGatewayResult> ServiceGateways;
        /// <summary>
        /// The service gateway's current state.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the service gateway belongs to.
        /// </summary>
        public readonly string? VcnId;

        [OutputConstructor]
        private GetServiceGatewaysResult(
            string compartmentId,

            ImmutableArray<Outputs.GetServiceGatewaysFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetServiceGatewaysServiceGatewayResult> serviceGateways,

            string? state,

            string? vcnId)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            ServiceGateways = serviceGateways;
            State = state;
            VcnId = vcnId;
        }
    }
}
