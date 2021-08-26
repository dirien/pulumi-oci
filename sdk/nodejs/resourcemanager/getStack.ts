// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Stack resource in Oracle Cloud Infrastructure Resource Manager service.
 *
 * Gets a stack using the stack ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testStack = oci.resourcemanager.getStack({
 *     stackId: oci_resourcemanager_stack.test_stack.id,
 * });
 * ```
 */
export function getStack(args: GetStackArgs, opts?: pulumi.InvokeOptions): Promise<GetStackResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:resourcemanager/getStack:getStack", {
        "stackId": args.stackId,
    }, opts);
}

/**
 * A collection of arguments for invoking getStack.
 */
export interface GetStackArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the stack.
     */
    stackId: string;
}

/**
 * A collection of values returned by getStack.
 */
export interface GetStackResult {
    /**
     * Unique identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) for the compartment where the stack is located.
     */
    readonly compartmentId: string;
    readonly configSources: outputs.resourcemanager.GetStackConfigSource[];
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * General description of the stack.
     */
    readonly description: string;
    /**
     * Human-readable display name for the stack.
     */
    readonly displayName: string;
    /**
     * Free-form tags associated with this resource. Each tag is a key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly stackId: string;
    /**
     * The current lifecycle state of the stack.
     */
    readonly state: string;
    /**
     * The date and time at which the stack was created.
     */
    readonly timeCreated: string;
    readonly variables: {[key: string]: any};
}
