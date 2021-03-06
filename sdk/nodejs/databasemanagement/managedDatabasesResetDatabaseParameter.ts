// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Managed Databases Reset Database Parameter resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Resets database parameter values to their default or startup values.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedDatabasesResetDatabaseParameter = new oci.databasemanagement.ManagedDatabasesResetDatabaseParameter("testManagedDatabasesResetDatabaseParameter", {
 *     credentials: {
 *         password: _var.managed_databases_reset_database_parameter_credentials_password,
 *         role: _var.managed_databases_reset_database_parameter_credentials_role,
 *         userName: oci_identity_user.test_user.name,
 *     },
 *     managedDatabaseId: oci_database_management_managed_database.test_managed_database.id,
 *     parameters: _var.managed_databases_reset_database_parameter_parameters,
 *     scope: _var.managed_databases_reset_database_parameter_scope,
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class ManagedDatabasesResetDatabaseParameter extends pulumi.CustomResource {
    /**
     * Get an existing ManagedDatabasesResetDatabaseParameter resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ManagedDatabasesResetDatabaseParameterState, opts?: pulumi.CustomResourceOptions): ManagedDatabasesResetDatabaseParameter {
        return new ManagedDatabasesResetDatabaseParameter(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:databasemanagement/managedDatabasesResetDatabaseParameter:ManagedDatabasesResetDatabaseParameter';

    /**
     * Returns true if the given object is an instance of ManagedDatabasesResetDatabaseParameter.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ManagedDatabasesResetDatabaseParameter {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ManagedDatabasesResetDatabaseParameter.__pulumiType;
    }

    /**
     * The database credentials used to perform management activity.
     */
    public readonly credentials!: pulumi.Output<outputs.databasemanagement.ManagedDatabasesResetDatabaseParameterCredentials>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    public readonly managedDatabaseId!: pulumi.Output<string>;
    /**
     * A list of database parameter names.
     */
    public readonly parameters!: pulumi.Output<string[]>;
    /**
     * The clause used to specify when the parameter change takes effect.
     */
    public readonly scope!: pulumi.Output<string>;

    /**
     * Create a ManagedDatabasesResetDatabaseParameter resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ManagedDatabasesResetDatabaseParameterArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ManagedDatabasesResetDatabaseParameterArgs | ManagedDatabasesResetDatabaseParameterState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ManagedDatabasesResetDatabaseParameterState | undefined;
            inputs["credentials"] = state ? state.credentials : undefined;
            inputs["managedDatabaseId"] = state ? state.managedDatabaseId : undefined;
            inputs["parameters"] = state ? state.parameters : undefined;
            inputs["scope"] = state ? state.scope : undefined;
        } else {
            const args = argsOrState as ManagedDatabasesResetDatabaseParameterArgs | undefined;
            if ((!args || args.credentials === undefined) && !opts.urn) {
                throw new Error("Missing required property 'credentials'");
            }
            if ((!args || args.managedDatabaseId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'managedDatabaseId'");
            }
            if ((!args || args.parameters === undefined) && !opts.urn) {
                throw new Error("Missing required property 'parameters'");
            }
            if ((!args || args.scope === undefined) && !opts.urn) {
                throw new Error("Missing required property 'scope'");
            }
            inputs["credentials"] = args ? args.credentials : undefined;
            inputs["managedDatabaseId"] = args ? args.managedDatabaseId : undefined;
            inputs["parameters"] = args ? args.parameters : undefined;
            inputs["scope"] = args ? args.scope : undefined;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(ManagedDatabasesResetDatabaseParameter.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ManagedDatabasesResetDatabaseParameter resources.
 */
export interface ManagedDatabasesResetDatabaseParameterState {
    /**
     * The database credentials used to perform management activity.
     */
    credentials?: pulumi.Input<inputs.databasemanagement.ManagedDatabasesResetDatabaseParameterCredentials>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId?: pulumi.Input<string>;
    /**
     * A list of database parameter names.
     */
    parameters?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The clause used to specify when the parameter change takes effect.
     */
    scope?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ManagedDatabasesResetDatabaseParameter resource.
 */
export interface ManagedDatabasesResetDatabaseParameterArgs {
    /**
     * The database credentials used to perform management activity.
     */
    credentials: pulumi.Input<inputs.databasemanagement.ManagedDatabasesResetDatabaseParameterCredentials>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     */
    managedDatabaseId: pulumi.Input<string>;
    /**
     * A list of database parameter names.
     */
    parameters: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The clause used to specify when the parameter change takes effect.
     */
    scope: pulumi.Input<string>;
}
