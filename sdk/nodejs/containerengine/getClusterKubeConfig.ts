// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Cluster Kube Config resource in Oracle Cloud Infrastructure Container Engine service.
 *
 * Create the Kubeconfig YAML for a cluster.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testClusterKubeConfig = oci.containerengine.getClusterKubeConfig({
 *     clusterId: oci_containerengine_cluster.test_cluster.id,
 *     endpoint: _var.cluster_kube_config_endpoint,
 *     expiration: _var.cluster_kube_config_expiration,
 *     tokenVersion: _var.cluster_kube_config_token_version,
 * });
 * ```
 */
export function getClusterKubeConfig(args: GetClusterKubeConfigArgs, opts?: pulumi.InvokeOptions): Promise<GetClusterKubeConfigResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:containerengine/getClusterKubeConfig:getClusterKubeConfig", {
        "clusterId": args.clusterId,
        "endpoint": args.endpoint,
        "expiration": args.expiration,
        "tokenVersion": args.tokenVersion,
    }, opts);
}

/**
 * A collection of arguments for invoking getClusterKubeConfig.
 */
export interface GetClusterKubeConfigArgs {
    /**
     * The OCID of the cluster.
     */
    clusterId: string;
    /**
     * The endpoint to target. A cluster may have multiple endpoints exposed but the kubeconfig can only target one at a time.
     */
    endpoint?: string;
    /**
     * Deprecated. This field is no longer used.
     */
    expiration?: number;
    /**
     * The version of the kubeconfig token. Supported value 2.0.0
     */
    tokenVersion?: string;
}

/**
 * A collection of values returned by getClusterKubeConfig.
 */
export interface GetClusterKubeConfigResult {
    readonly clusterId: string;
    /**
     * content of the Kubeconfig YAML for the cluster.
     */
    readonly content: string;
    readonly endpoint?: string;
    readonly expiration?: number;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly tokenVersion?: string;
}
