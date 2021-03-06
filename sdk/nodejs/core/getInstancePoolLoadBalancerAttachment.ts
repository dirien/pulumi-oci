// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Instance Pool Load Balancer Attachment resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets information about a load balancer that is attached to the specified instance pool.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInstancePoolLoadBalancerAttachment = oci.core.getInstancePoolLoadBalancerAttachment({
 *     instancePoolId: oci_core_instance_pool.test_instance_pool.id,
 *     instancePoolLoadBalancerAttachmentId: oci_core_instance_pool_load_balancer_attachment.test_instance_pool_load_balancer_attachment.id,
 * });
 * ```
 */
export function getInstancePoolLoadBalancerAttachment(args: GetInstancePoolLoadBalancerAttachmentArgs, opts?: pulumi.InvokeOptions): Promise<GetInstancePoolLoadBalancerAttachmentResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:core/getInstancePoolLoadBalancerAttachment:getInstancePoolLoadBalancerAttachment", {
        "instancePoolId": args.instancePoolId,
        "instancePoolLoadBalancerAttachmentId": args.instancePoolLoadBalancerAttachmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInstancePoolLoadBalancerAttachment.
 */
export interface GetInstancePoolLoadBalancerAttachmentArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
     */
    instancePoolId: string;
    /**
     * The OCID of the load balancer attachment.
     */
    instancePoolLoadBalancerAttachmentId: string;
}

/**
 * A collection of values returned by getInstancePoolLoadBalancerAttachment.
 */
export interface GetInstancePoolLoadBalancerAttachmentResult {
    /**
     * The name of the backend set on the load balancer.
     */
    readonly backendSetName: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool of the load balancer attachment.
     */
    readonly instancePoolId: string;
    readonly instancePoolLoadBalancerAttachmentId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer attached to the instance pool.
     */
    readonly loadBalancerId: string;
    /**
     * The port value used for the backends.
     */
    readonly port: number;
    /**
     * The status of the interaction between the instance pool and the load balancer.
     */
    readonly state: string;
    /**
     * Indicates which VNIC on each instance in the instance pool should be used to associate with the load balancer. Possible values are "PrimaryVnic" or the displayName of one of the secondary VNICs on the instance configuration that is associated with the instance pool.
     */
    readonly vnicSelection: string;
}
