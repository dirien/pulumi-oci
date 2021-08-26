// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    public static class GetModelProvenance
    {
        /// <summary>
        /// This data source provides details about a specific Model Provenance resource in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Gets provenance information for specified model.
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
        ///         var testModelProvenance = Output.Create(Oci.DataScience.GetModelProvenance.InvokeAsync(new Oci.DataScience.GetModelProvenanceArgs
        ///         {
        ///             ModelId = oci_datascience_model.Test_model.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetModelProvenanceResult> InvokeAsync(GetModelProvenanceArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetModelProvenanceResult>("oci:datascience/getModelProvenance:getModelProvenance", args ?? new GetModelProvenanceArgs(), options.WithVersion());
    }


    public sealed class GetModelProvenanceArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
        /// </summary>
        [Input("modelId", required: true)]
        public string ModelId { get; set; } = null!;

        public GetModelProvenanceArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetModelProvenanceResult
    {
        /// <summary>
        /// For model reproducibility purposes. Branch of the git repository associated with model training.
        /// </summary>
        public readonly string GitBranch;
        /// <summary>
        /// For model reproducibility purposes. Commit ID of the git repository associated with model training.
        /// </summary>
        public readonly string GitCommit;
        public readonly string Id;
        public readonly string ModelId;
        /// <summary>
        /// For model reproducibility purposes. URL of the git repository associated with model training.
        /// </summary>
        public readonly string RepositoryUrl;
        /// <summary>
        /// For model reproducibility purposes. Path to model artifacts.
        /// </summary>
        public readonly string ScriptDir;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a training session(Job or NotebookSession) in which the model was trained. It is used for model reproducibility purposes.
        /// </summary>
        public readonly string TrainingId;
        /// <summary>
        /// For model reproducibility purposes. Path to the python script or notebook in which the model was trained."
        /// </summary>
        public readonly string TrainingScript;

        [OutputConstructor]
        private GetModelProvenanceResult(
            string gitBranch,

            string gitCommit,

            string id,

            string modelId,

            string repositoryUrl,

            string scriptDir,

            string trainingId,

            string trainingScript)
        {
            GitBranch = gitBranch;
            GitCommit = gitCommit;
            Id = id;
            ModelId = modelId;
            RepositoryUrl = repositoryUrl;
            ScriptDir = scriptDir;
            TrainingId = trainingId;
            TrainingScript = trainingScript;
        }
    }
}