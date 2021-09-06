// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Purge Cache resource in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
 *
 * Performs a purge of the cache for each specified resource. If no resources are passed, the cache for the entire Web Application Firewall will be purged.
 * For more information, see [Caching Rules](https://docs.cloud.oracle.com/iaas/Content/WAF/Tasks/cachingrules.htm#purge).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPurgeCache = new oci.waas.PurgeCache("testPurgeCache", {
 *     waasPolicyId: oci_waas_waas_policy.test_waas_policy.id,
 *     resources: _var.purge_cache_resources,
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class PurgeCache extends pulumi.CustomResource {
    /**
     * Get an existing PurgeCache resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PurgeCacheState, opts?: pulumi.CustomResourceOptions): PurgeCache {
        return new PurgeCache(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:waas/purgeCache:PurgeCache';

    /**
     * Returns true if the given object is an instance of PurgeCache.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PurgeCache {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PurgeCache.__pulumiType;
    }

    /**
     * A resource to purge, specified by either a hostless absolute path starting with a single slash (Example: `/path/to/resource`) or by a relative path in which the first component will be interpreted as a domain protected by the WAAS policy (Example: `example.com/path/to/resource`).
     */
    public readonly resources!: pulumi.Output<string[] | undefined>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
     */
    public readonly waasPolicyId!: pulumi.Output<string>;

    /**
     * Create a PurgeCache resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PurgeCacheArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PurgeCacheArgs | PurgeCacheState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as PurgeCacheState | undefined;
            inputs["resources"] = state ? state.resources : undefined;
            inputs["waasPolicyId"] = state ? state.waasPolicyId : undefined;
        } else {
            const args = argsOrState as PurgeCacheArgs | undefined;
            if ((!args || args.waasPolicyId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'waasPolicyId'");
            }
            inputs["resources"] = args ? args.resources : undefined;
            inputs["waasPolicyId"] = args ? args.waasPolicyId : undefined;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(PurgeCache.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PurgeCache resources.
 */
export interface PurgeCacheState {
    /**
     * A resource to purge, specified by either a hostless absolute path starting with a single slash (Example: `/path/to/resource`) or by a relative path in which the first component will be interpreted as a domain protected by the WAAS policy (Example: `example.com/path/to/resource`).
     */
    resources?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
     */
    waasPolicyId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a PurgeCache resource.
 */
export interface PurgeCacheArgs {
    /**
     * A resource to purge, specified by either a hostless absolute path starting with a single slash (Example: `/path/to/resource`) or by a relative path in which the first component will be interpreted as a domain protected by the WAAS policy (Example: `example.com/path/to/resource`).
     */
    resources?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
     */
    waasPolicyId: pulumi.Input<string>;
}
