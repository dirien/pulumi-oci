// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Autonomous Database Regional Wallet Management resource in Oracle Cloud Infrastructure Database service.
 *
 * Updates the Autonomous Database regional wallet.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousDatabaseRegionalWalletManagement = new oci.database.AutonomousDatabaseRegionalWalletManagement("testAutonomousDatabaseRegionalWalletManagement", {shouldRotate: _var.autonomous_database_regional_wallet_management_should_rotate});
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class AutonomousDatabaseRegionalWalletManagement extends pulumi.CustomResource {
    /**
     * Get an existing AutonomousDatabaseRegionalWalletManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AutonomousDatabaseRegionalWalletManagementState, opts?: pulumi.CustomResourceOptions): AutonomousDatabaseRegionalWalletManagement {
        return new AutonomousDatabaseRegionalWalletManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:database/autonomousDatabaseRegionalWalletManagement:AutonomousDatabaseRegionalWalletManagement';

    /**
     * Returns true if the given object is an instance of AutonomousDatabaseRegionalWalletManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AutonomousDatabaseRegionalWalletManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AutonomousDatabaseRegionalWalletManagement.__pulumiType;
    }

    /**
     * (Updatable) Indicates whether to rotate the wallet or not. If `false`, the wallet will not be rotated. The default is `false`.
     */
    public readonly shouldRotate!: pulumi.Output<boolean | undefined>;
    /**
     * The current lifecycle state of the Autonomous Database wallet.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the wallet was last rotated.
     */
    public /*out*/ readonly timeRotated!: pulumi.Output<string>;

    /**
     * Create a AutonomousDatabaseRegionalWalletManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: AutonomousDatabaseRegionalWalletManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AutonomousDatabaseRegionalWalletManagementArgs | AutonomousDatabaseRegionalWalletManagementState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AutonomousDatabaseRegionalWalletManagementState | undefined;
            inputs["shouldRotate"] = state ? state.shouldRotate : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["timeRotated"] = state ? state.timeRotated : undefined;
        } else {
            const args = argsOrState as AutonomousDatabaseRegionalWalletManagementArgs | undefined;
            inputs["shouldRotate"] = args ? args.shouldRotate : undefined;
            inputs["state"] = undefined /*out*/;
            inputs["timeRotated"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(AutonomousDatabaseRegionalWalletManagement.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AutonomousDatabaseRegionalWalletManagement resources.
 */
export interface AutonomousDatabaseRegionalWalletManagementState {
    /**
     * (Updatable) Indicates whether to rotate the wallet or not. If `false`, the wallet will not be rotated. The default is `false`.
     */
    shouldRotate?: pulumi.Input<boolean>;
    /**
     * The current lifecycle state of the Autonomous Database wallet.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the wallet was last rotated.
     */
    timeRotated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AutonomousDatabaseRegionalWalletManagement resource.
 */
export interface AutonomousDatabaseRegionalWalletManagementArgs {
    /**
     * (Updatable) Indicates whether to rotate the wallet or not. If `false`, the wallet will not be rotated. The default is `false`.
     */
    shouldRotate?: pulumi.Input<boolean>;
}