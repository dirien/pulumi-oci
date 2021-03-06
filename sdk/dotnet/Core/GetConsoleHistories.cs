// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetConsoleHistories
    {
        /// <summary>
        /// This data source provides the list of Console Histories in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the console history metadata for the specified compartment or instance.
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
        ///         var testConsoleHistories = Output.Create(Oci.Core.GetConsoleHistories.InvokeAsync(new Oci.Core.GetConsoleHistoriesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             AvailabilityDomain = @var.Console_history_availability_domain,
        ///             InstanceId = oci_core_instance.Test_instance.Id,
        ///             State = @var.Console_history_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetConsoleHistoriesResult> InvokeAsync(GetConsoleHistoriesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetConsoleHistoriesResult>("oci:core/getConsoleHistories:getConsoleHistories", args ?? new GetConsoleHistoriesArgs(), options.WithVersion());
    }


    public sealed class GetConsoleHistoriesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public string? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetConsoleHistoriesFilterArgs>? _filters;
        public List<Inputs.GetConsoleHistoriesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetConsoleHistoriesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the instance.
        /// </summary>
        [Input("instanceId")]
        public string? InstanceId { get; set; }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetConsoleHistoriesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetConsoleHistoriesResult
    {
        /// <summary>
        /// The availability domain of an instance.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string? AvailabilityDomain;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of console_histories.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetConsoleHistoriesConsoleHistoryResult> ConsoleHistories;
        public readonly ImmutableArray<Outputs.GetConsoleHistoriesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the instance this console history was fetched from.
        /// </summary>
        public readonly string? InstanceId;
        /// <summary>
        /// The current state of the console history.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetConsoleHistoriesResult(
            string? availabilityDomain,

            string compartmentId,

            ImmutableArray<Outputs.GetConsoleHistoriesConsoleHistoryResult> consoleHistories,

            ImmutableArray<Outputs.GetConsoleHistoriesFilterResult> filters,

            string id,

            string? instanceId,

            string? state)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            ConsoleHistories = consoleHistories;
            Filters = filters;
            Id = id;
            InstanceId = instanceId;
            State = state;
        }
    }
}
