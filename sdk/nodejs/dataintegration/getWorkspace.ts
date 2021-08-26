// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Workspace resource in Oracle Cloud Infrastructure Data Integration service.
 *
 * Retrieves a Data Integration workspace using the specified identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWorkspace = oci.dataintegration.getWorkspace({
 *     workspaceId: oci_dataintegration_workspace.test_workspace.id,
 * });
 * ```
 */
export function getWorkspace(args: GetWorkspaceArgs, opts?: pulumi.InvokeOptions): Promise<GetWorkspaceResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:dataintegration/getWorkspace:getWorkspace", {
        "workspaceId": args.workspaceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getWorkspace.
 */
export interface GetWorkspaceArgs {
    /**
     * The workspace ID.
     */
    workspaceId: string;
}

/**
 * A collection of values returned by getWorkspace.
 */
export interface GetWorkspaceResult {
    /**
     * The OCID of the compartment that contains the workspace.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * A user defined description for the workspace.
     */
    readonly description: string;
    /**
     * A user-friendly display name for the workspace. Does not have to be unique, and can be modified. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * The IP of the custom DNS.
     */
    readonly dnsServerIp: string;
    /**
     * The DNS zone of the custom DNS to use to resolve names.
     */
    readonly dnsServerZone: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * A system-generated and immutable identifier assigned to the workspace upon creation.
     */
    readonly id: string;
    readonly isForceOperation: boolean;
    /**
     * Specifies whether the private network connection is enabled or disabled.
     */
    readonly isPrivateNetworkEnabled: boolean;
    readonly quiesceTimeout: number;
    /**
     * Lifecycle states for workspaces in Data Integration Service CREATING - The resource is being created and may not be usable until the entire metadata is defined UPDATING - The resource is being updated and may not be usable until all changes are commited DELETING - The resource is being deleted and might require deep cleanup of children. ACTIVE   - The resource is valid and available for access INACTIVE - The resource might be incomplete in its definition or might have been made unavailable for administrative reasons DELETED  - The resource has been deleted and isn't available FAILED   - The resource is in a failed state due to validation or other errors STARTING - The resource is being started and may not be usable until becomes ACTIVE again STOPPING - The resource is in the process of Stopping and may not be usable until it Stops or fails STOPPED  - The resource is in Stopped state due to stop operation.
     */
    readonly state: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in failed state.
     */
    readonly stateMessage: string;
    /**
     * The OCID of the subnet for customer connected databases.
     */
    readonly subnetId: string;
    /**
     * The date and time the workspace was created, in the timestamp format defined by RFC3339.
     */
    readonly timeCreated: string;
    /**
     * The date and time the workspace was updated, in the timestamp format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     */
    readonly timeUpdated: string;
    /**
     * The OCID of the VCN the subnet is in.
     */
    readonly vcnId: string;
    readonly workspaceId: string;
}
