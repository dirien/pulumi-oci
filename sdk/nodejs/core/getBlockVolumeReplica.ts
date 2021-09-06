// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Block Volume Replica resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets information for the specified block volume replica.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBlockVolumeReplica = oci.core.getBlockVolumeReplica({
 *     blockVolumeReplicaId: oci_core_block_volume_replica.test_block_volume_replica.id,
 * });
 * ```
 */
export function getBlockVolumeReplica(args: GetBlockVolumeReplicaArgs, opts?: pulumi.InvokeOptions): Promise<GetBlockVolumeReplicaResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:core/getBlockVolumeReplica:getBlockVolumeReplica", {
        "blockVolumeReplicaId": args.blockVolumeReplicaId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBlockVolumeReplica.
 */
export interface GetBlockVolumeReplicaArgs {
    /**
     * The OCID of the block volume replica.
     */
    blockVolumeReplicaId: string;
}

/**
 * A collection of values returned by getBlockVolumeReplica.
 */
export interface GetBlockVolumeReplicaResult {
    /**
     * The availability domain of the block volume replica.  Example: `Uocm:PHX-AD-1`
     */
    readonly availabilityDomain: string;
    /**
     * The OCID of the source block volume.
     */
    readonly blockVolumeId: string;
    readonly blockVolumeReplicaId: string;
    /**
     * The OCID of the compartment that contains the block volume replica.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The size of the source block volume, in GBs.
     */
    readonly sizeInGbs: string;
    /**
     * The current state of a block volume replica.
     */
    readonly state: string;
    /**
     * The date and time the block volume replica was created. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeCreated: string;
    /**
     * The date and time the block volume replica was last synced from the source block volume. Format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeLastSynced: string;
}
