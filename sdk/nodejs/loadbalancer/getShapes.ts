// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Load Balancer Shapes in Oracle Cloud Infrastructure Load Balancer service.
 *
 * Lists the valid load balancer shapes.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testLoadBalancerShapes = oci.loadbalancer.getShapes({
 *     compartmentId: _var.compartment_id,
 * });
 * ```
 */
export function getShapes(args: GetShapesArgs, opts?: pulumi.InvokeOptions): Promise<GetShapesResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:loadbalancer/getShapes:getShapes", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getShapes.
 */
export interface GetShapesArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the load balancer shapes to list.
     */
    compartmentId: string;
    filters?: inputs.loadbalancer.GetShapesFilter[];
}

/**
 * A collection of values returned by getShapes.
 */
export interface GetShapesResult {
    readonly compartmentId: string;
    readonly filters?: outputs.loadbalancer.GetShapesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of shapes.
     */
    readonly shapes: outputs.loadbalancer.GetShapesShape[];
}
