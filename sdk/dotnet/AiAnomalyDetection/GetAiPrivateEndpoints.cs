// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiAnomalyDetection
{
    public static class GetAiPrivateEndpoints
    {
        /// <summary>
        /// This data source provides the list of Ai Private Endpoints in Oracle Cloud Infrastructure Ai Anomaly Detection service.
        /// 
        /// Returns a list of all the AI private endpoints in the specified compartment.
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
        ///         var testAiPrivateEndpoints = Output.Create(Oci.AiAnomalyDetection.GetAiPrivateEndpoints.InvokeAsync(new Oci.AiAnomalyDetection.GetAiPrivateEndpointsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Ai_private_endpoint_display_name,
        ///             Id = @var.Ai_private_endpoint_id,
        ///             State = @var.Ai_private_endpoint_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAiPrivateEndpointsResult> InvokeAsync(GetAiPrivateEndpointsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAiPrivateEndpointsResult>("oci:aianomalydetection/getAiPrivateEndpoints:getAiPrivateEndpoints", args ?? new GetAiPrivateEndpointsArgs(), options.WithVersion());
    }


    public sealed class GetAiPrivateEndpointsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetAiPrivateEndpointsFilterArgs>? _filters;
        public List<Inputs.GetAiPrivateEndpointsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAiPrivateEndpointsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// unique AiPrivateEndpoint identifier
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetAiPrivateEndpointsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetAiPrivateEndpointsResult
    {
        /// <summary>
        /// The list of ai_private_endpoint_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAiPrivateEndpointsAiPrivateEndpointCollectionResult> AiPrivateEndpointCollections;
        /// <summary>
        /// Compartment Identifier.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Private Reverse Connection Endpoint display name.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetAiPrivateEndpointsFilterResult> Filters;
        /// <summary>
        /// Unique identifier that is immutable.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The current state of the private endpoint resource.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetAiPrivateEndpointsResult(
            ImmutableArray<Outputs.GetAiPrivateEndpointsAiPrivateEndpointCollectionResult> aiPrivateEndpointCollections,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetAiPrivateEndpointsFilterResult> filters,

            string? id,

            string? state)
        {
            AiPrivateEndpointCollections = aiPrivateEndpointCollections;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
