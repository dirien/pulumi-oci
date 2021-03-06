// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    public static class GetModelDeploymentShapes
    {
        /// <summary>
        /// This data source provides the list of Model Deployment Shapes in Oracle Cloud Infrastructure Datascience service.
        /// 
        /// Lists the valid model deployment shapes.
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
        ///         var testModelDeploymentShapes = Output.Create(Oci.DataScience.GetModelDeploymentShapes.InvokeAsync(new Oci.DataScience.GetModelDeploymentShapesArgs
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
        public static Task<GetModelDeploymentShapesResult> InvokeAsync(GetModelDeploymentShapesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetModelDeploymentShapesResult>("oci:datascience/getModelDeploymentShapes:getModelDeploymentShapes", args ?? new GetModelDeploymentShapesArgs(), options.WithVersion());
    }


    public sealed class GetModelDeploymentShapesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetModelDeploymentShapesFilterArgs>? _filters;
        public List<Inputs.GetModelDeploymentShapesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetModelDeploymentShapesFilterArgs>());
            set => _filters = value;
        }

        public GetModelDeploymentShapesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetModelDeploymentShapesResult
    {
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetModelDeploymentShapesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of model_deployment_shapes.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelDeploymentShapesModelDeploymentShapeResult> ModelDeploymentShapes;

        [OutputConstructor]
        private GetModelDeploymentShapesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetModelDeploymentShapesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetModelDeploymentShapesModelDeploymentShapeResult> modelDeploymentShapes)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            ModelDeploymentShapes = modelDeploymentShapes;
        }
    }
}
