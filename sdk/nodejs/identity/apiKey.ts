// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Api Key resource in Oracle Cloud Infrastructure Identity service.
 *
 * Uploads an API signing key for the specified user.
 *
 * Every user has permission to use this operation to upload a key for *their own user ID*. An
 * administrator in your organization does not need to write a policy to give users this ability.
 * To compare, administrators who have permission to the tenancy can use this operation to upload a
 * key for any user, including themselves.
 *
 * **Important:** Even though you have permission to upload an API key, you might not yet
 * have permission to do much else. If you try calling an operation unrelated to your own credential
 * management (e.g., `ListUsers`, `LaunchInstance`) and receive an "unauthorized" error,
 * check with an administrator to confirm which IAM Service group(s) you're in and what access
 * you have. Also confirm you're working in the correct compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testApiKey = new oci.identity.ApiKey("testApiKey", {
 *     keyValue: _var.api_key_key_value,
 *     userId: oci_identity_user.test_user.id,
 * });
 * ```
 *
 * ## Import
 *
 * ApiKeys can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:identity/apiKey:ApiKey test_api_key "users/{userId}/apiKeys/{fingerprint}"
 * ```
 */
export class ApiKey extends pulumi.CustomResource {
    /**
     * Get an existing ApiKey resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ApiKeyState, opts?: pulumi.CustomResourceOptions): ApiKey {
        return new ApiKey(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:identity/apiKey:ApiKey';

    /**
     * Returns true if the given object is an instance of ApiKey.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ApiKey {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ApiKey.__pulumiType;
    }

    /**
     * The key's fingerprint (e.g., 12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef).
     */
    public /*out*/ readonly fingerprint!: pulumi.Output<string>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    public /*out*/ readonly inactiveStatus!: pulumi.Output<string>;
    /**
     * The public key.  Must be an RSA key in PEM format.
     */
    public readonly keyValue!: pulumi.Output<string>;
    /**
     * The API key's current state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * Date and time the `ApiKey` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The OCID of the user.
     */
    public readonly userId!: pulumi.Output<string>;

    /**
     * Create a ApiKey resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ApiKeyArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ApiKeyArgs | ApiKeyState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ApiKeyState | undefined;
            inputs["fingerprint"] = state ? state.fingerprint : undefined;
            inputs["inactiveStatus"] = state ? state.inactiveStatus : undefined;
            inputs["keyValue"] = state ? state.keyValue : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["userId"] = state ? state.userId : undefined;
        } else {
            const args = argsOrState as ApiKeyArgs | undefined;
            if ((!args || args.keyValue === undefined) && !opts.urn) {
                throw new Error("Missing required property 'keyValue'");
            }
            if ((!args || args.userId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'userId'");
            }
            inputs["keyValue"] = args ? args.keyValue : undefined;
            inputs["userId"] = args ? args.userId : undefined;
            inputs["fingerprint"] = undefined /*out*/;
            inputs["inactiveStatus"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(ApiKey.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ApiKey resources.
 */
export interface ApiKeyState {
    /**
     * The key's fingerprint (e.g., 12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef).
     */
    fingerprint?: pulumi.Input<string>;
    /**
     * The detailed status of INACTIVE lifecycleState.
     */
    inactiveStatus?: pulumi.Input<string>;
    /**
     * The public key.  Must be an RSA key in PEM format.
     */
    keyValue?: pulumi.Input<string>;
    /**
     * The API key's current state.
     */
    state?: pulumi.Input<string>;
    /**
     * Date and time the `ApiKey` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The OCID of the user.
     */
    userId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ApiKey resource.
 */
export interface ApiKeyArgs {
    /**
     * The public key.  Must be an RSA key in PEM format.
     */
    keyValue: pulumi.Input<string>;
    /**
     * The OCID of the user.
     */
    userId: pulumi.Input<string>;
}
