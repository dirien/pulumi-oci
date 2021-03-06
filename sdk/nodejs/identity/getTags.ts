// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Tags in Oracle Cloud Infrastructure Identity service.
 *
 * Lists the tag definitions in the specified tag namespace.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTags = oci.identity.getTags({
 *     tagNamespaceId: oci_identity_tag_namespace.test_tag_namespace.id,
 *     state: _var.tag_state,
 * });
 * ```
 */
export function getTags(args: GetTagsArgs, opts?: pulumi.InvokeOptions): Promise<GetTagsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:identity/getTags:getTags", {
        "filters": args.filters,
        "state": args.state,
        "tagNamespaceId": args.tagNamespaceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getTags.
 */
export interface GetTagsArgs {
    filters?: inputs.identity.GetTagsFilter[];
    /**
     * A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     */
    state?: string;
    /**
     * The OCID of the tag namespace.
     */
    tagNamespaceId: string;
}

/**
 * A collection of values returned by getTags.
 */
export interface GetTagsResult {
    readonly filters?: outputs.identity.GetTagsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The tag's current state. After creating a tag, make sure its `lifecycleState` is ACTIVE before using it. After retiring a tag, make sure its `lifecycleState` is INACTIVE before using it. If you delete a tag, you cannot delete another tag until the deleted tag's `lifecycleState` changes from DELETING to DELETED.
     */
    readonly state?: string;
    /**
     * The OCID of the namespace that contains the tag definition.
     */
    readonly tagNamespaceId: string;
    /**
     * The list of tags.
     */
    readonly tags: outputs.identity.GetTagsTag[];
}
