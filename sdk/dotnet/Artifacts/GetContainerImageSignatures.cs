// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Artifacts
{
    public static class GetContainerImageSignatures
    {
        /// <summary>
        /// This data source provides the list of Container Image Signatures in Oracle Cloud Infrastructure Artifacts service.
        /// 
        /// List container image signatures in an image.
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
        ///         var testContainerImageSignatures = Output.Create(Oci.Artifacts.GetContainerImageSignatures.InvokeAsync(new Oci.Artifacts.GetContainerImageSignaturesArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///             CompartmentIdInSubtree = @var.Container_image_signature_compartment_id_in_subtree,
        ///             DisplayName = @var.Container_image_signature_display_name,
        ///             ImageDigest = @var.Container_image_signature_image_digest,
        ///             ImageId = oci_core_image.Test_image.Id,
        ///             KmsKeyId = oci_kms_key.Test_key.Id,
        ///             KmsKeyVersionId = oci_kms_key_version.Test_key_version.Id,
        ///             RepositoryId = oci_artifacts_repository.Test_repository.Id,
        ///             RepositoryName = oci_artifacts_repository.Test_repository.Name,
        ///             SigningAlgorithm = @var.Container_image_signature_signing_algorithm,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetContainerImageSignaturesResult> InvokeAsync(GetContainerImageSignaturesArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetContainerImageSignaturesResult>("oci:artifacts/getContainerImageSignatures:getContainerImageSignatures", args ?? new GetContainerImageSignaturesArgs(), options.WithVersion());
    }


    public sealed class GetContainerImageSignaturesArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are inspected depending on the the setting of `accessLevel`. Default is false. Can only be set to true when calling the API on the tenancy (root compartment).
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public bool? CompartmentIdInSubtree { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetContainerImageSignaturesFilterArgs>? _filters;
        public List<Inputs.GetContainerImageSignaturesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetContainerImageSignaturesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The digest of the container image.  Example: `sha256:e7d38b3517548a1c71e41bffe9c8ae6d6d29546ce46bf62159837aad072c90aa`
        /// </summary>
        [Input("imageDigest")]
        public string? ImageDigest { get; set; }

        /// <summary>
        /// A filter to return a container image summary only for the specified container image OCID.
        /// </summary>
        [Input("imageId")]
        public string? ImageId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyVersionId used to sign the container image.  Example: `ocid1.keyversion.oc1..exampleuniqueID`
        /// </summary>
        [Input("kmsKeyId")]
        public string? KmsKeyId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyVersionId used to sign the container image.  Example: `ocid1.keyversion.oc1..exampleuniqueID`
        /// </summary>
        [Input("kmsKeyVersionId")]
        public string? KmsKeyVersionId { get; set; }

        /// <summary>
        /// A filter to return container images only for the specified container repository OCID.
        /// </summary>
        [Input("repositoryId")]
        public string? RepositoryId { get; set; }

        /// <summary>
        /// A filter to return container images or container image signatures that match the repository name.  Example: `foo` or `foo*`
        /// </summary>
        [Input("repositoryName")]
        public string? RepositoryName { get; set; }

        /// <summary>
        /// The algorithm to be used for signing. These are the only supported signing algorithms for container images.
        /// </summary>
        [Input("signingAlgorithm")]
        public string? SigningAlgorithm { get; set; }

        public GetContainerImageSignaturesArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetContainerImageSignaturesResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the container repository exists.
        /// </summary>
        public readonly string CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        /// <summary>
        /// The list of container_image_signature_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetContainerImageSignaturesContainerImageSignatureCollectionResult> ContainerImageSignatureCollections;
        /// <summary>
        /// The last 10 characters of the kmsKeyId, the last 10 characters of the kmsKeyVersionId, the signingAlgorithm, and the last 10 characters of the signatureId.  Example: `wrmz22sixa::qdwyc2ptun::SHA_256_RSA_PKCS_PSS::2vwmobasva`
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetContainerImageSignaturesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? ImageDigest;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image.  Example: `ocid1.containerimage.oc1..exampleuniqueID`
        /// </summary>
        public readonly string? ImageId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyId used to sign the container image.  Example: `ocid1.key.oc1..exampleuniqueID`
        /// </summary>
        public readonly string? KmsKeyId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyVersionId used to sign the container image.  Example: `ocid1.keyversion.oc1..exampleuniqueID`
        /// </summary>
        public readonly string? KmsKeyVersionId;
        public readonly string? RepositoryId;
        public readonly string? RepositoryName;
        /// <summary>
        /// The algorithm to be used for signing. These are the only supported signing algorithms for container images.
        /// </summary>
        public readonly string? SigningAlgorithm;

        [OutputConstructor]
        private GetContainerImageSignaturesResult(
            string compartmentId,

            bool? compartmentIdInSubtree,

            ImmutableArray<Outputs.GetContainerImageSignaturesContainerImageSignatureCollectionResult> containerImageSignatureCollections,

            string? displayName,

            ImmutableArray<Outputs.GetContainerImageSignaturesFilterResult> filters,

            string id,

            string? imageDigest,

            string? imageId,

            string? kmsKeyId,

            string? kmsKeyVersionId,

            string? repositoryId,

            string? repositoryName,

            string? signingAlgorithm)
        {
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            ContainerImageSignatureCollections = containerImageSignatureCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            ImageDigest = imageDigest;
            ImageId = imageId;
            KmsKeyId = kmsKeyId;
            KmsKeyVersionId = kmsKeyVersionId;
            RepositoryId = repositoryId;
            RepositoryName = repositoryName;
            SigningAlgorithm = signingAlgorithm;
        }
    }
}
