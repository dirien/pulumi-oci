// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Backend Set resource in Oracle Cloud Infrastructure Network Load Balancer service.
 *
 * Retrieves the configuration information for the specified backend set.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBackendSet = oci.networkloadbalancer.getBackendSet({
 *     backendSetName: oci_network_load_balancer_backend_set.test_backend_set.name,
 *     networkLoadBalancerId: oci_network_load_balancer_network_load_balancer.test_network_load_balancer.id,
 * });
 * ```
 */
export function getBackendSet(args: GetBackendSetArgs, opts?: pulumi.InvokeOptions): Promise<GetBackendSetResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:networkloadbalancer/getBackendSet:getBackendSet", {
        "backendSetName": args.backendSetName,
        "networkLoadBalancerId": args.networkLoadBalancerId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBackendSet.
 */
export interface GetBackendSetArgs {
    /**
     * The name of the backend set to retrieve.  Example: `exampleBackendSet`
     */
    backendSetName: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
     */
    networkLoadBalancerId: string;
}

/**
 * A collection of values returned by getBackendSet.
 */
export interface GetBackendSetResult {
    readonly backendSetName: string;
    /**
     * Array of backends.
     */
    readonly backends: outputs.networkloadbalancer.GetBackendSetBackend[];
    /**
     * The health check policy configuration. For more information, see [Editing Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/editinghealthcheck.htm).
     */
    readonly healthChecker: outputs.networkloadbalancer.GetBackendSetHealthChecker;
    readonly id: string;
    /**
     * If this parameter is enabled, then the network load balancer preserves the source IP of the packet when it is forwarded to backends. Backends see the original source IP. If the isPreserveSourceDestination parameter is enabled for the network load balancer resource, then this parameter cannot be disabled. The value is true by default.
     */
    readonly isPreserveSource: boolean;
    /**
     * A user-friendly name for the backend set that must be unique and cannot be changed.
     */
    readonly name: string;
    readonly networkLoadBalancerId: string;
    /**
     * The network load balancer policy for the backend set.  Example: `FIVE_TUPLE`
     */
    readonly policy: string;
}
