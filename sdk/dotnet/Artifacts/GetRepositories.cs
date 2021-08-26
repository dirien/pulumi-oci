// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Artifacts
{
    public static class GetRepositories
    {
        /// <summary>
        /// This data source provides the list of Repositories in Oracle Cloud Infrastructure Artifacts service.
        /// 
        /// Lists repositories in the specified compartment.
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
        ///         var testRepositories = Output.Create(Oci.Artifacts.GetRepositories.InvokeAsync(new Oci.Artifacts.GetRepositoriesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Repository_display_name,
        ///             Id = @var.Repository_id,
        ///             IsImmutable = @var.Repository_is_immutable,
        ///             State = @var.Repository_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetRepositoriesResult> InvokeAsync(GetRepositoriesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetRepositoriesResult>("oci:artifacts/getRepositories:getRepositories", args ?? new GetRepositoriesArgs(), options.WithVersion());
    }


    public sealed class GetRepositoriesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetRepositoriesFilterArgs>? _filters;
        public List<Inputs.GetRepositoriesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetRepositoriesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return the resources for the specified OCID.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to return resources that match the isImmutable value.
        /// </summary>
        [Input("isImmutable")]
        public bool? IsImmutable { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state name exactly.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetRepositoriesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetRepositoriesResult
    {
        /// <summary>
        /// The OCID of the repository's compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The repository name.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetRepositoriesFilterResult> Filters;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository.  Example: `ocid1.artifactrepository.oc1..exampleuniqueID`
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// Whether the repository is immutable. The artifacts of an immutable repository cannot be overwritten.
        /// </summary>
        public readonly bool? IsImmutable;
        /// <summary>
        /// The list of repository_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRepositoriesRepositoryCollectionResult> RepositoryCollections;
        /// <summary>
        /// The current state of the repository.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetRepositoriesResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetRepositoriesFilterResult> filters,

            string? id,

            bool? isImmutable,

            ImmutableArray<Outputs.GetRepositoriesRepositoryCollectionResult> repositoryCollections,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            IsImmutable = isImmutable;
            RepositoryCollections = repositoryCollections;
            State = state;
        }
    }
}
