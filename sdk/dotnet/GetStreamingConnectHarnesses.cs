// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    public static class GetStreamingConnectHarnesses
    {
        /// <summary>
        /// This data source provides the list of Connect Harnesses in Oracle Cloud Infrastructure Streaming service.
        /// 
        /// Lists the connectharness.
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
        ///         var testConnectHarnesses = Output.Create(Oci.GetStreamingConnectHarnesses.InvokeAsync(new Oci.GetStreamingConnectHarnessesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Id = @var.Connect_harness_id,
        ///             Name = @var.Connect_harness_name,
        ///             State = @var.Connect_harness_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetStreamingConnectHarnessesResult> InvokeAsync(GetStreamingConnectHarnessesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetStreamingConnectHarnessesResult>("oci:index/getStreamingConnectHarnesses:GetStreamingConnectHarnesses", args ?? new GetStreamingConnectHarnessesArgs(), options.WithVersion());
    }


    public sealed class GetStreamingConnectHarnessesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetStreamingConnectHarnessesFilterArgs>? _filters;
        public List<Inputs.GetStreamingConnectHarnessesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetStreamingConnectHarnessesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given ID exactly.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given name exactly.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetStreamingConnectHarnessesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetStreamingConnectHarnessesResult
    {
        /// <summary>
        /// The OCID of the compartment that contains the connect harness.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of connect_harness.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetStreamingConnectHarnessesConnectHarnessResult> ConnectHarnesses;
        public readonly ImmutableArray<Outputs.GetStreamingConnectHarnessesFilterResult> Filters;
        /// <summary>
        /// The OCID of the connect harness.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The name of the connect harness. Avoid entering confidential information.  Example: `JDBCConnector`
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The current state of the connect harness.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetStreamingConnectHarnessesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetStreamingConnectHarnessesConnectHarnessResult> connectHarnesses,

            ImmutableArray<Outputs.GetStreamingConnectHarnessesFilterResult> filters,

            string? id,

            string? name,

            string? state)
        {
            CompartmentId = compartmentId;
            ConnectHarnesses = connectHarnesses;
            Filters = filters;
            Id = id;
            Name = name;
            State = state;
        }
    }
}