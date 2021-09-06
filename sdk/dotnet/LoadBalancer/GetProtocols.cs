// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer
{
    public static class GetProtocols
    {
        /// <summary>
        /// This data source provides the list of Load Balancer Protocols in Oracle Cloud Infrastructure Load Balancer service.
        /// 
        /// Lists all supported traffic protocols.
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
        ///         var testLoadBalancerProtocols = Output.Create(Oci.LoadBalancer.GetProtocols.InvokeAsync(new Oci.LoadBalancer.GetProtocolsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetProtocolsResult> InvokeAsync(GetProtocolsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetProtocolsResult>("oci:loadbalancer/getProtocols:getProtocols", args ?? new GetProtocolsArgs(), options.WithVersion());
    }


    public sealed class GetProtocolsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the load balancer protocols to list.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetProtocolsFilterArgs>? _filters;
        public List<Inputs.GetProtocolsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetProtocolsFilterArgs>());
            set => _filters = value;
        }

        public GetProtocolsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetProtocolsResult
    {
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetProtocolsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of protocols.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetProtocolsProtocolResult> Protocols;

        [OutputConstructor]
        private GetProtocolsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetProtocolsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetProtocolsProtocolResult> protocols)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            Protocols = protocols;
        }
    }
}
