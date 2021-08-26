// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ObjectStorage
{
    public static class GetBucketSummaries
    {
        /// <summary>
        /// This data source provides the list of Buckets in Oracle Cloud Infrastructure Object Storage service.
        /// 
        /// Gets a list of all BucketSummary items in a compartment. A BucketSummary contains only summary fields for the bucket
        /// and does not contain fields like the user-defined metadata.
        /// 
        /// ListBuckets returns a BucketSummary containing at most 1000 buckets. To paginate through more buckets, use the returned
        /// `opc-next-page` value with the `page` request parameter.
        /// 
        /// To use this and other API operations, you must be authorized in an IAM policy. If you are not authorized,
        /// talk to an administrator. If you are an administrator who needs to write policies to give users access, see
        /// [Getting Started with Policies](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm).
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
        ///         var testBuckets = Output.Create(Oci.ObjectStorage.GetBucketSummaries.InvokeAsync(new Oci.ObjectStorage.GetBucketSummariesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             Namespace = @var.Bucket_namespace,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetBucketSummariesResult> InvokeAsync(GetBucketSummariesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetBucketSummariesResult>("oci:objectstorage/getBucketSummaries:getBucketSummaries", args ?? new GetBucketSummariesArgs(), options.WithVersion());
    }


    public sealed class GetBucketSummariesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list buckets.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetBucketSummariesFilterArgs>? _filters;
        public List<Inputs.GetBucketSummariesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetBucketSummariesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The Object Storage namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        public GetBucketSummariesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetBucketSummariesResult
    {
        /// <summary>
        /// The list of bucket_summaries.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBucketSummariesBucketSummaryResult> BucketSummaries;
        /// <summary>
        /// The compartment ID in which the bucket is authorized.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetBucketSummariesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The Object Storage namespace in which the bucket resides.
        /// </summary>
        public readonly string Namespace;

        [OutputConstructor]
        private GetBucketSummariesResult(
            ImmutableArray<Outputs.GetBucketSummariesBucketSummaryResult> bucketSummaries,

            string compartmentId,

            ImmutableArray<Outputs.GetBucketSummariesFilterResult> filters,

            string id,

            string @namespace)
        {
            BucketSummaries = bucketSummaries;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            Namespace = @namespace;
        }
    }
}
