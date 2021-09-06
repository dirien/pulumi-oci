// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ObjectStorage
{
    public static class GetBucket
    {
        /// <summary>
        /// This data source provides details about a specific Bucket resource in Oracle Cloud Infrastructure Object Storage service.
        /// 
        /// Gets the current representation of the given bucket in the given Object Storage namespace.
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
        ///         var testBucket = Output.Create(Oci.ObjectStorage.GetBucket.InvokeAsync(new Oci.ObjectStorage.GetBucketArgs
        ///         {
        ///             Name = @var.Bucket_name,
        ///             Namespace = @var.Bucket_namespace,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetBucketResult> InvokeAsync(GetBucketArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetBucketResult>("oci:objectstorage/getBucket:getBucket", args ?? new GetBucketArgs(), options.WithVersion());
    }


    public sealed class GetBucketArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the bucket. Avoid entering confidential information. Example: `my-new-bucket1`
        /// </summary>
        [Input("name", required: true)]
        public string Name { get; set; } = null!;

        /// <summary>
        /// The Object Storage namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        public GetBucketArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetBucketResult
    {
        /// <summary>
        /// The type of public access enabled on this bucket. A bucket is set to `NoPublicAccess` by default, which only allows an authenticated caller to access the bucket and its contents. When `ObjectRead` is enabled on the bucket, public access is allowed for the `GetObject`, `HeadObject`, and `ListObjects` operations. When `ObjectReadWithoutList` is enabled on the bucket, public access is allowed for the `GetObject` and `HeadObject` operations.
        /// </summary>
        public readonly string AccessType;
        /// <summary>
        /// The approximate number of objects in the bucket. Count statistics are reported periodically. You will see a lag between what is displayed and the actual object count.
        /// </summary>
        public readonly string ApproximateCount;
        /// <summary>
        /// The approximate total size in bytes of all objects in the bucket. Size statistics are reported periodically. You will see a lag between what is displayed and the actual size of the bucket.
        /// </summary>
        public readonly string ApproximateSize;
        /// <summary>
        /// The auto tiering status on the bucket. A bucket is created with auto tiering `Disabled` by default. For auto tiering `InfrequentAccess`, objects are transitioned automatically between the 'Standard' and 'InfrequentAccess' tiers based on the access pattern of the objects.
        /// </summary>
        public readonly string AutoTiering;
        /// <summary>
        /// The OCID of the bucket which is a Oracle assigned unique identifier for this resource type (bucket). `bucket_id` cannot be used for bucket lookup.
        /// </summary>
        public readonly string BucketId;
        /// <summary>
        /// The compartment ID in which the bucket is authorized.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the bucket.
        /// </summary>
        public readonly string CreatedBy;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The entity tag (ETag) for the bucket.
        /// </summary>
        public readonly string Etag;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        public readonly string Id;
        /// <summary>
        /// Whether or not this bucket is read only. By default, `isReadOnly` is set to `false`. This will be set to 'true' when this bucket is configured as a destination in a replication policy.
        /// </summary>
        public readonly bool IsReadOnly;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a master encryption key used to call the Key Management service to generate a data encryption key or to encrypt or decrypt a data encryption key.
        /// </summary>
        public readonly string KmsKeyId;
        /// <summary>
        /// Arbitrary string keys and values for user-defined metadata.
        /// </summary>
        public readonly ImmutableDictionary<string, object> Metadata;
        /// <summary>
        /// The name of the bucket. Avoid entering confidential information. Example: my-new-bucket1
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The Object Storage namespace in which the bucket resides.
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// Whether or not events are emitted for object state changes in this bucket. By default, `objectEventsEnabled` is set to `false`. Set `objectEventsEnabled` to `true` to emit events for object state changes. For more information about events, see [Overview of Events](https://docs.cloud.oracle.com/iaas/Content/Events/Concepts/eventsoverview.htm).
        /// </summary>
        public readonly bool ObjectEventsEnabled;
        /// <summary>
        /// The entity tag (ETag) for the live object lifecycle policy on the bucket.
        /// </summary>
        public readonly string ObjectLifecyclePolicyEtag;
        /// <summary>
        /// Whether or not this bucket is a replication source. By default, `replicationEnabled` is set to `false`. This will be set to 'true' when you create a replication policy for the bucket.
        /// </summary>
        public readonly bool ReplicationEnabled;
        /// <summary>
        /// User specified list of retention rules for the bucket.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBucketRetentionRuleResult> RetentionRules;
        /// <summary>
        /// The storage tier type assigned to the bucket. A bucket is set to `Standard` tier by default, which means objects uploaded or copied to the bucket will be in the standard storage tier. When the `Archive` tier type is set explicitly for a bucket, objects uploaded or copied to the bucket will be stored in archive storage. The `storageTier` property is immutable after bucket is created.
        /// </summary>
        public readonly string StorageTier;
        /// <summary>
        /// The date and time the bucket was created, as described in [RFC 2616](https://tools.ietf.org/html/rfc2616#section-14.29).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The versioning status on the bucket. A bucket is created with versioning `Disabled` by default. For versioning `Enabled`, objects are protected from overwrites and deletes, by maintaining their version history. When versioning is `Suspended`, the previous versions will still remain but new versions will no longer be created when overwitten or deleted.
        /// </summary>
        public readonly string Versioning;

        [OutputConstructor]
        private GetBucketResult(
            string accessType,

            string approximateCount,

            string approximateSize,

            string autoTiering,

            string bucketId,

            string compartmentId,

            string createdBy,

            ImmutableDictionary<string, object> definedTags,

            string etag,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            bool isReadOnly,

            string kmsKeyId,

            ImmutableDictionary<string, object> metadata,

            string name,

            string @namespace,

            bool objectEventsEnabled,

            string objectLifecyclePolicyEtag,

            bool replicationEnabled,

            ImmutableArray<Outputs.GetBucketRetentionRuleResult> retentionRules,

            string storageTier,

            string timeCreated,

            string versioning)
        {
            AccessType = accessType;
            ApproximateCount = approximateCount;
            ApproximateSize = approximateSize;
            AutoTiering = autoTiering;
            BucketId = bucketId;
            CompartmentId = compartmentId;
            CreatedBy = createdBy;
            DefinedTags = definedTags;
            Etag = etag;
            FreeformTags = freeformTags;
            Id = id;
            IsReadOnly = isReadOnly;
            KmsKeyId = kmsKeyId;
            Metadata = metadata;
            Name = name;
            Namespace = @namespace;
            ObjectEventsEnabled = objectEventsEnabled;
            ObjectLifecyclePolicyEtag = objectLifecyclePolicyEtag;
            ReplicationEnabled = replicationEnabled;
            RetentionRules = retentionRules;
            StorageTier = storageTier;
            TimeCreated = timeCreated;
            Versioning = versioning;
        }
    }
}
