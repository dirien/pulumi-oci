// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Artifacts
{
    public static class GetRepository
    {
        /// <summary>
        /// This data source provides details about a specific Repository resource in Oracle Cloud Infrastructure Artifacts service.
        /// 
        /// Gets the specified repository's information.
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
        ///         var testRepository = Output.Create(Oci.Artifacts.GetRepository.InvokeAsync(new Oci.Artifacts.GetRepositoryArgs
        ///         {
        ///             RepositoryId = oci_artifacts_repository.Test_repository.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetRepositoryResult> InvokeAsync(GetRepositoryArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetRepositoryResult>("oci:artifacts/getRepository:getRepository", args ?? new GetRepositoryArgs(), options.WithVersion());
    }


    public sealed class GetRepositoryArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository.  Example: `ocid1.artifactrepository.oc1..exampleuniqueID`
        /// </summary>
        [Input("repositoryId", required: true)]
        public string RepositoryId { get; set; } = null!;

        public GetRepositoryArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetRepositoryResult
    {
        /// <summary>
        /// The OCID of the repository's compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The repository description.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The repository name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository.  Example: `ocid1.artifactrepository.oc1..exampleuniqueID`
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Whether the repository is immutable. The artifacts of an immutable repository cannot be overwritten.
        /// </summary>
        public readonly bool IsImmutable;
        public readonly string RepositoryId;
        /// <summary>
        /// The repository's supported artifact type.
        /// </summary>
        public readonly string RepositoryType;
        /// <summary>
        /// The current state of the repository.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// An RFC 3339 timestamp indicating when the repository was created.
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetRepositoryResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            bool isImmutable,

            string repositoryId,

            string repositoryType,

            string state,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IsImmutable = isImmutable;
            RepositoryId = repositoryId;
            RepositoryType = repositoryType;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}
