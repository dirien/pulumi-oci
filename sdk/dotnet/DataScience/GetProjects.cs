// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    public static class GetProjects
    {
        /// <summary>
        /// This data source provides the list of Projects in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Lists projects in the specified compartment.
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
        ///         var testProjects = Output.Create(Oci.DataScience.GetProjects.InvokeAsync(new Oci.DataScience.GetProjectsArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             CreatedBy = @var.Project_created_by,
        ///             DisplayName = @var.Project_display_name,
        ///             Id = @var.Project_id,
        ///             State = @var.Project_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetProjectsResult> InvokeAsync(GetProjectsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetProjectsResult>("oci:datascience/getProjects:getProjects", args ?? new GetProjectsArgs(), options.WithVersion());
    }


    public sealed class GetProjectsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
        /// </summary>
        [Input("createdBy")]
        public string? CreatedBy { get; set; }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetProjectsFilterArgs>? _filters;
        public List<Inputs.GetProjectsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetProjectsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetProjectsArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetProjectsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project's compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created this project.
        /// </summary>
        public readonly string? CreatedBy;
        /// <summary>
        /// A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetProjectsFilterResult> Filters;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The list of projects.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetProjectsProjectResult> Projects;
        /// <summary>
        /// The state of the project.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetProjectsResult(
            string compartmentId,

            string? createdBy,

            string? displayName,

            ImmutableArray<Outputs.GetProjectsFilterResult> filters,

            string? id,

            ImmutableArray<Outputs.GetProjectsProjectResult> projects,

            string? state)
        {
            CompartmentId = compartmentId;
            CreatedBy = createdBy;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            Projects = projects;
            State = state;
        }
    }
}
