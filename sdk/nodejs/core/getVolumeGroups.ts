// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Volume Groups in Oracle Cloud Infrastructure Core service.
 *
 * Lists the volume groups in the specified compartment and availability domain.
 * For more information, see [Volume Groups](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/volumegroups.htm).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVolumeGroups = oci.core.getVolumeGroups({
 *     compartmentId: _var.compartment_id,
 *     availabilityDomain: _var.volume_group_availability_domain,
 *     displayName: _var.volume_group_display_name,
 *     state: _var.volume_group_state,
 * });
 * ```
 */
export function getVolumeGroups(args: GetVolumeGroupsArgs, opts?: pulumi.InvokeOptions): Promise<GetVolumeGroupsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:core/getVolumeGroups:getVolumeGroups", {
        "availabilityDomain": args.availabilityDomain,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getVolumeGroups.
 */
export interface GetVolumeGroupsArgs {
    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     */
    availabilityDomain?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.core.GetVolumeGroupsFilter[];
    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: string;
}

/**
 * A collection of values returned by getVolumeGroups.
 */
export interface GetVolumeGroupsResult {
    /**
     * The availability domain of the volume group.
     */
    readonly availabilityDomain?: string;
    /**
     * The OCID of the compartment that contains the volume group.
     */
    readonly compartmentId: string;
    /**
     * A user-friendly name for the volume group. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.core.GetVolumeGroupsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of a volume group.
     */
    readonly state?: string;
    /**
     * The list of volume_groups.
     */
    readonly volumeGroups: outputs.core.GetVolumeGroupsVolumeGroup[];
}
