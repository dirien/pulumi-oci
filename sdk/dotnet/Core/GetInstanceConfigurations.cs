// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetInstanceConfigurations
    {
        /// <summary>
        /// This data source provides the list of Instance Configurations in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the instance configurations in the specified compartment.
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
        ///         var testInstanceConfigurations = Output.Create(Oci.Core.GetInstanceConfigurations.InvokeAsync(new Oci.Core.GetInstanceConfigurationsArgs
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
        public static Task<GetInstanceConfigurationsResult> InvokeAsync(GetInstanceConfigurationsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetInstanceConfigurationsResult>("oci:core/getInstanceConfigurations:getInstanceConfigurations", args ?? new GetInstanceConfigurationsArgs(), options.WithVersion());
    }


    public sealed class GetInstanceConfigurationsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetInstanceConfigurationsFilterArgs>? _filters;
        public List<Inputs.GetInstanceConfigurationsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetInstanceConfigurationsFilterArgs>());
            set => _filters = value;
        }

        public GetInstanceConfigurationsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetInstanceConfigurationsResult
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetInstanceConfigurationsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of instance_configurations.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInstanceConfigurationsInstanceConfigurationResult> InstanceConfigurations;

        [OutputConstructor]
        private GetInstanceConfigurationsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetInstanceConfigurationsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetInstanceConfigurationsInstanceConfigurationResult> instanceConfigurations)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            InstanceConfigurations = instanceConfigurations;
        }
    }
}
