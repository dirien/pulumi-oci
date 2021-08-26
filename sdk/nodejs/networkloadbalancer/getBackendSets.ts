// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Backend Sets in Oracle Cloud Infrastructure Network Load Balancer service.
 *
 * Lists all backend sets associated with a given network load balancer.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBackendSets = oci.networkloadbalancer.getBackendSets({
 *     networkLoadBalancerId: oci_network_load_balancer_network_load_balancer.test_network_load_balancer.id,
 * });
 * ```
 */
export function getBackendSets(args: GetBackendSetsArgs, opts?: pulumi.InvokeOptions): Promise<GetBackendSetsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:networkloadbalancer/getBackendSets:getBackendSets", {
        "filters": args.filters,
        "networkLoadBalancerId": args.networkLoadBalancerId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBackendSets.
 */
export interface GetBackendSetsArgs {
    filters?: inputs.networkloadbalancer.GetBackendSetsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     */
    networkLoadBalancerId: string;
}

/**
 * A collection of values returned by getBackendSets.
 */
export interface GetBackendSetsResult {
    /**
     * The list of backend_set_collection.
     */
    readonly backendSetCollections: outputs.networkloadbalancer.GetBackendSetsBackendSetCollection[];
    readonly filters?: outputs.networkloadbalancer.GetBackendSetsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly networkLoadBalancerId: string;
}