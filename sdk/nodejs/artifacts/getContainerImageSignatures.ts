// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Container Image Signatures in Oracle Cloud Infrastructure Artifacts service.
 *
 * List container image signatures in an image.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testContainerImageSignatures = oci.artifacts.getContainerImageSignatures({
 *     compartmentId: _var.compartment_id,
 *     compartmentIdInSubtree: _var.container_image_signature_compartment_id_in_subtree,
 *     displayName: _var.container_image_signature_display_name,
 *     imageDigest: _var.container_image_signature_image_digest,
 *     imageId: oci_core_image.test_image.id,
 *     kmsKeyId: oci_kms_key.test_key.id,
 *     kmsKeyVersionId: oci_kms_key_version.test_key_version.id,
 *     repositoryId: oci_artifacts_repository.test_repository.id,
 *     repositoryName: oci_artifacts_repository.test_repository.name,
 *     signingAlgorithm: _var.container_image_signature_signing_algorithm,
 * });
 * ```
 */
export function getContainerImageSignatures(args: GetContainerImageSignaturesArgs, opts?: pulumi.InvokeOptions): Promise<GetContainerImageSignaturesResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:artifacts/getContainerImageSignatures:getContainerImageSignatures", {
        "compartmentId": args.compartmentId,
        "compartmentIdInSubtree": args.compartmentIdInSubtree,
        "displayName": args.displayName,
        "filters": args.filters,
        "imageDigest": args.imageDigest,
        "imageId": args.imageId,
        "kmsKeyId": args.kmsKeyId,
        "kmsKeyVersionId": args.kmsKeyVersionId,
        "repositoryId": args.repositoryId,
        "repositoryName": args.repositoryName,
        "signingAlgorithm": args.signingAlgorithm,
    }, opts);
}

/**
 * A collection of arguments for invoking getContainerImageSignatures.
 */
export interface GetContainerImageSignaturesArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are inspected depending on the the setting of `accessLevel`. Default is false. Can only be set to true when calling the API on the tenancy (root compartment).
     */
    compartmentIdInSubtree?: boolean;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.artifacts.GetContainerImageSignaturesFilter[];
    /**
     * The digest of the container image.  Example: `sha256:e7d38b3517548a1c71e41bffe9c8ae6d6d29546ce46bf62159837aad072c90aa`
     */
    imageDigest?: string;
    /**
     * A filter to return a container image summary only for the specified container image OCID.
     */
    imageId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyVersionId used to sign the container image.  Example: `ocid1.keyversion.oc1..exampleuniqueID`
     */
    kmsKeyId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyVersionId used to sign the container image.  Example: `ocid1.keyversion.oc1..exampleuniqueID`
     */
    kmsKeyVersionId?: string;
    /**
     * A filter to return container images only for the specified container repository OCID.
     */
    repositoryId?: string;
    /**
     * A filter to return container images or container image signatures that match the repository name.  Example: `foo` or `foo*`
     */
    repositoryName?: string;
    /**
     * The algorithm to be used for signing. These are the only supported signing algorithms for container images.
     */
    signingAlgorithm?: string;
}

/**
 * A collection of values returned by getContainerImageSignatures.
 */
export interface GetContainerImageSignaturesResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the container repository exists.
     */
    readonly compartmentId: string;
    readonly compartmentIdInSubtree?: boolean;
    /**
     * The list of container_image_signature_collection.
     */
    readonly containerImageSignatureCollections: outputs.artifacts.GetContainerImageSignaturesContainerImageSignatureCollection[];
    /**
     * The last 10 characters of the kmsKeyId, the last 10 characters of the kmsKeyVersionId, the signingAlgorithm, and the last 10 characters of the signatureId.  Example: `wrmz22sixa::qdwyc2ptun::SHA_256_RSA_PKCS_PSS::2vwmobasva`
     */
    readonly displayName?: string;
    readonly filters?: outputs.artifacts.GetContainerImageSignaturesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly imageDigest?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image.  Example: `ocid1.containerimage.oc1..exampleuniqueID`
     */
    readonly imageId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyId used to sign the container image.  Example: `ocid1.key.oc1..exampleuniqueID`
     */
    readonly kmsKeyId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyVersionId used to sign the container image.  Example: `ocid1.keyversion.oc1..exampleuniqueID`
     */
    readonly kmsKeyVersionId?: string;
    readonly repositoryId?: string;
    readonly repositoryName?: string;
    /**
     * The algorithm to be used for signing. These are the only supported signing algorithms for container images.
     */
    readonly signingAlgorithm?: string;
}
