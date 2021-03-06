// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Bds Instance resource in Oracle Cloud Infrastructure Big Data Service service.
 *
 * Returns information about the Big Data Service cluster identified by the given ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBdsInstance = oci.bds.getBdsInstance({
 *     bdsInstanceId: oci_bds_bds_instance.test_bds_instance.id,
 * });
 * ```
 */
export function getBdsInstance(args: GetBdsInstanceArgs, opts?: pulumi.InvokeOptions): Promise<GetBdsInstanceResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:bds/getBdsInstance:getBdsInstance", {
        "bdsInstanceId": args.bdsInstanceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBdsInstance.
 */
export interface GetBdsInstanceArgs {
    /**
     * The OCID of the cluster.
     */
    bdsInstanceId: string;
}

/**
 * A collection of values returned by getBdsInstance.
 */
export interface GetBdsInstanceResult {
    readonly bdsInstanceId: string;
    /**
     * The information about added Cloud SQL capability
     */
    readonly cloudSqlDetails: outputs.bds.GetBdsInstanceCloudSqlDetails;
    readonly clusterAdminPassword: string;
    /**
     * Specific info about a Hadoop cluster
     */
    readonly clusterDetails: outputs.bds.GetBdsInstanceClusterDetails;
    readonly clusterPublicKey: string;
    /**
     * Version of the Hadoop distribution.
     */
    readonly clusterVersion: string;
    /**
     * The OCID of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The user who created the cluster.
     */
    readonly createdBy: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For example, `{"foo-namespace": {"bar-key": "value"}}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * The name of the node.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. For example, `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The OCID of the Big Data Service resource.
     */
    readonly id: string;
    /**
     * Boolean flag specifying whether or not Cloud SQL should be configured.
     */
    readonly isCloudSqlConfigured: boolean;
    /**
     * Boolean flag specifying whether or not the cluster is highly available (HA)
     */
    readonly isHighAvailability: boolean;
    /**
     * Boolean flag specifying whether or not the cluster should be set up as secure.
     */
    readonly isSecure: boolean;
    readonly masterNode: outputs.bds.GetBdsInstanceMasterNode;
    /**
     * Additional configuration of the user's network.
     */
    readonly networkConfig: outputs.bds.GetBdsInstanceNetworkConfig;
    /**
     * The list of nodes in the cluster.
     */
    readonly nodes: outputs.bds.GetBdsInstanceNode[];
    /**
     * The number of nodes that form the cluster.
     */
    readonly numberOfNodes: number;
    /**
     * The state of the cluster.
     */
    readonly state: string;
    /**
     * The time the cluster was created, shown as an RFC 3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time the cluster was updated, shown as an RFC 3339 formatted datetime string.
     */
    readonly timeUpdated: string;
    readonly utilNode: outputs.bds.GetBdsInstanceUtilNode;
    readonly workerNode: outputs.bds.GetBdsInstanceWorkerNode;
}
