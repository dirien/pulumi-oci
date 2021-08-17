// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci
{
    public static class GetCoreDrgs
    {
        /// <summary>
        /// This data source provides the list of Drgs in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the DRGs in the specified compartment.
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
        ///         var testDrgs = Output.Create(Oci.GetCoreDrgs.InvokeAsync(new Oci.GetCoreDrgsArgs
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
        public static Task<GetCoreDrgsResult> InvokeAsync(GetCoreDrgsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetCoreDrgsResult>("oci:index/getCoreDrgs:GetCoreDrgs", args ?? new GetCoreDrgsArgs(), options.WithVersion());
    }


    public sealed class GetCoreDrgsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetCoreDrgsFilterArgs>? _filters;
        public List<Inputs.GetCoreDrgsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetCoreDrgsFilterArgs>());
            set => _filters = value;
        }

        public GetCoreDrgsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetCoreDrgsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the DRG.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The list of drgs.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetCoreDrgsDrgResult> Drgs;
        public readonly ImmutableArray<Outputs.GetCoreDrgsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetCoreDrgsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetCoreDrgsDrgResult> drgs,

            ImmutableArray<Outputs.GetCoreDrgsFilterResult> filters,

            string id)
        {
            CompartmentId = compartmentId;
            Drgs = drgs;
            Filters = filters;
            Id = id;
        }
    }
}