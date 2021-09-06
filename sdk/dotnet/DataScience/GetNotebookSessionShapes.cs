// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    public static class GetNotebookSessionShapes
    {
        /// <summary>
        /// This data source provides the list of Notebook Session Shapes in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Lists the valid notebook session shapes.
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
        ///         var testNotebookSessionShapes = Output.Create(Oci.DataScience.GetNotebookSessionShapes.InvokeAsync(new Oci.DataScience.GetNotebookSessionShapesArgs
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
        public static Task<GetNotebookSessionShapesResult> InvokeAsync(GetNotebookSessionShapesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetNotebookSessionShapesResult>("oci:datascience/getNotebookSessionShapes:getNotebookSessionShapes", args ?? new GetNotebookSessionShapesArgs(), options.WithVersion());
    }


    public sealed class GetNotebookSessionShapesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetNotebookSessionShapesFilterArgs>? _filters;
        public List<Inputs.GetNotebookSessionShapesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetNotebookSessionShapesFilterArgs>());
            set => _filters = value;
        }

        public GetNotebookSessionShapesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetNotebookSessionShapesResult
    {
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetNotebookSessionShapesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of notebook_session_shapes.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNotebookSessionShapesNotebookSessionShapeResult> NotebookSessionShapes;

        [OutputConstructor]
        private GetNotebookSessionShapesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetNotebookSessionShapesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetNotebookSessionShapesNotebookSessionShapeResult> notebookSessionShapes)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            NotebookSessionShapes = notebookSessionShapes;
        }
    }
}
