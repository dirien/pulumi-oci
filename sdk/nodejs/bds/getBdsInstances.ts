// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Bds Instances in Oracle Cloud Infrastructure Big Data Service service.
 *
 * Returns a list of all Big Data Service clusters in a compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBdsInstances = oci.bds.getBdsInstances({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.bds_instance_display_name,
 *     state: _var.bds_instance_state,
 * });
 * ```
 */
export function getBdsInstances(args: GetBdsInstancesArgs, opts?: pulumi.InvokeOptions): Promise<GetBdsInstancesResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:bds/getBdsInstances:getBdsInstances", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getBdsInstances.
 */
export interface GetBdsInstancesArgs {
    /**
     * The OCID of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.bds.GetBdsInstancesFilter[];
    /**
     * The state of the cluster.
     */
    state?: string;
}

/**
 * A collection of values returned by getBdsInstances.
 */
export interface GetBdsInstancesResult {
    /**
     * The list of bds_instances.
     */
    readonly bdsInstances: outputs.bds.GetBdsInstancesBdsInstance[];
    /**
     * The OCID of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The name of the node.
     */
    readonly displayName?: string;
    readonly filters?: outputs.bds.GetBdsInstancesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The state of the cluster.
     */
    readonly state?: string;
}
