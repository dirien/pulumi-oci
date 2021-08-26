// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Tag Defaults in Oracle Cloud Infrastructure Identity service.
 *
 * Lists the tag defaults for tag definitions in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTagDefaults = oci.identity.getTagDefaults({
 *     compartmentId: _var.compartment_id,
 *     id: _var.tag_default_id,
 *     state: _var.tag_default_state,
 *     tagDefinitionId: oci_identity_tag_definition.test_tag_definition.id,
 * });
 * ```
 */
export function getTagDefaults(args?: GetTagDefaultsArgs, opts?: pulumi.InvokeOptions): Promise<GetTagDefaultsResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:identity/getTagDefaults:getTagDefaults", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "id": args.id,
        "state": args.state,
        "tagDefinitionId": args.tagDefinitionId,
    }, opts);
}

/**
 * A collection of arguments for invoking getTagDefaults.
 */
export interface GetTagDefaultsArgs {
    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     */
    compartmentId?: string;
    filters?: inputs.identity.GetTagDefaultsFilter[];
    /**
     * A filter to only return resources that match the specified OCID exactly.
     */
    id?: string;
    /**
     * A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     */
    state?: string;
    /**
     * The OCID of the tag definition.
     */
    tagDefinitionId?: string;
}

/**
 * A collection of values returned by getTagDefaults.
 */
export interface GetTagDefaultsResult {
    /**
     * The OCID of the compartment. The tag default applies to all new resources that get created in the compartment. Resources that existed before the tag default was created are not tagged.
     */
    readonly compartmentId?: string;
    readonly filters?: outputs.identity.GetTagDefaultsFilter[];
    /**
     * The OCID of the tag default.
     */
    readonly id?: string;
    /**
     * The tag default's current state. After creating a `TagDefault`, make sure its `lifecycleState` is ACTIVE before using it.
     */
    readonly state?: string;
    /**
     * The list of tag_defaults.
     */
    readonly tagDefaults: outputs.identity.GetTagDefaultsTagDefault[];
    /**
     * The OCID of the tag definition. The tag default will always assign a default value for this tag definition.
     */
    readonly tagDefinitionId?: string;
}
