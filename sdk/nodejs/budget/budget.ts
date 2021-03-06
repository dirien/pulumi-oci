// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Budget resource in Oracle Cloud Infrastructure Budget service.
 *
 * Creates a new Budget.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBudget = new oci.budget.Budget("testBudget", {
 *     amount: _var.budget_amount,
 *     compartmentId: _var.tenancy_ocid,
 *     resetPeriod: _var.budget_reset_period,
 *     budgetProcessingPeriodStartOffset: _var.budget_budget_processing_period_start_offset,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     description: _var.budget_description,
 *     displayName: _var.budget_display_name,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 *     targetCompartmentId: oci_identity_compartment.test_compartment.id,
 *     targetType: _var.budget_target_type,
 *     targets: _var.budget_targets,
 * });
 * ```
 *
 * ## Import
 *
 * Budgets can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:budget/budget:Budget test_budget "id"
 * ```
 */
export class Budget extends pulumi.CustomResource {
    /**
     * Get an existing Budget resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: BudgetState, opts?: pulumi.CustomResourceOptions): Budget {
        return new Budget(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:budget/budget:Budget';

    /**
     * Returns true if the given object is an instance of Budget.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Budget {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Budget.__pulumiType;
    }

    /**
     * The actual spend in currency for the current budget cycle
     */
    public /*out*/ readonly actualSpend!: pulumi.Output<number>;
    /**
     * Total number of alert rules in the budget
     */
    public /*out*/ readonly alertRuleCount!: pulumi.Output<number>;
    /**
     * (Updatable) The amount of the budget expressed as a whole number in the currency of the customer's rate card.
     */
    public readonly amount!: pulumi.Output<number>;
    /**
     * (Updatable) The number of days offset from the first day of the month, at which the budget processing period starts. In months that have fewer days than this value, processing will begin on the last day of that month. For example, for a value of 12, processing starts every month on the 12th at midnight.
     */
    public readonly budgetProcessingPeriodStartOffset!: pulumi.Output<number>;
    /**
     * The OCID of the tenancy
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The description of the budget.
     */
    public readonly description!: pulumi.Output<string>;
    /**
     * (Updatable) The displayName of the budget.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The forecasted spend in currency by the end of the current budget cycle
     */
    public /*out*/ readonly forecastedSpend!: pulumi.Output<number>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The reset period for the budget. Valid value is MONTHLY.
     */
    public readonly resetPeriod!: pulumi.Output<string>;
    /**
     * The current state of the budget.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * This is DEPRECTAED. Set the target compartment id in targets instead.
     *
     * @deprecated The 'target_compartment_id' field has been deprecated. Please use 'target_type' instead.
     */
    public readonly targetCompartmentId!: pulumi.Output<string>;
    /**
     * The type of target on which the budget is applied.
     */
    public readonly targetType!: pulumi.Output<string>;
    /**
     * The list of targets on which the budget is applied. If targetType is "COMPARTMENT", targets contains list of compartment OCIDs. If targetType is "TAG", targets contains list of cost tracking tag identifiers in the form of "{tagNamespace}.{tagKey}.{tagValue}". Curerntly, the array should contain EXACT ONE item.
     */
    public readonly targets!: pulumi.Output<string[]>;
    /**
     * Time that budget was created
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time that the budget spend was last computed
     */
    public /*out*/ readonly timeSpendComputed!: pulumi.Output<string>;
    /**
     * Time that budget was updated
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * Version of the budget. Starts from 1 and increments by 1.
     */
    public /*out*/ readonly version!: pulumi.Output<number>;

    /**
     * Create a Budget resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: BudgetArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: BudgetArgs | BudgetState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as BudgetState | undefined;
            inputs["actualSpend"] = state ? state.actualSpend : undefined;
            inputs["alertRuleCount"] = state ? state.alertRuleCount : undefined;
            inputs["amount"] = state ? state.amount : undefined;
            inputs["budgetProcessingPeriodStartOffset"] = state ? state.budgetProcessingPeriodStartOffset : undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["definedTags"] = state ? state.definedTags : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["forecastedSpend"] = state ? state.forecastedSpend : undefined;
            inputs["freeformTags"] = state ? state.freeformTags : undefined;
            inputs["resetPeriod"] = state ? state.resetPeriod : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["targetCompartmentId"] = state ? state.targetCompartmentId : undefined;
            inputs["targetType"] = state ? state.targetType : undefined;
            inputs["targets"] = state ? state.targets : undefined;
            inputs["timeCreated"] = state ? state.timeCreated : undefined;
            inputs["timeSpendComputed"] = state ? state.timeSpendComputed : undefined;
            inputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            inputs["version"] = state ? state.version : undefined;
        } else {
            const args = argsOrState as BudgetArgs | undefined;
            if ((!args || args.amount === undefined) && !opts.urn) {
                throw new Error("Missing required property 'amount'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.resetPeriod === undefined) && !opts.urn) {
                throw new Error("Missing required property 'resetPeriod'");
            }
            inputs["amount"] = args ? args.amount : undefined;
            inputs["budgetProcessingPeriodStartOffset"] = args ? args.budgetProcessingPeriodStartOffset : undefined;
            inputs["compartmentId"] = args ? args.compartmentId : undefined;
            inputs["definedTags"] = args ? args.definedTags : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["freeformTags"] = args ? args.freeformTags : undefined;
            inputs["resetPeriod"] = args ? args.resetPeriod : undefined;
            inputs["targetCompartmentId"] = args ? args.targetCompartmentId : undefined;
            inputs["targetType"] = args ? args.targetType : undefined;
            inputs["targets"] = args ? args.targets : undefined;
            inputs["actualSpend"] = undefined /*out*/;
            inputs["alertRuleCount"] = undefined /*out*/;
            inputs["forecastedSpend"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["timeCreated"] = undefined /*out*/;
            inputs["timeSpendComputed"] = undefined /*out*/;
            inputs["timeUpdated"] = undefined /*out*/;
            inputs["version"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(Budget.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Budget resources.
 */
export interface BudgetState {
    /**
     * The actual spend in currency for the current budget cycle
     */
    actualSpend?: pulumi.Input<number>;
    /**
     * Total number of alert rules in the budget
     */
    alertRuleCount?: pulumi.Input<number>;
    /**
     * (Updatable) The amount of the budget expressed as a whole number in the currency of the customer's rate card.
     */
    amount?: pulumi.Input<number>;
    /**
     * (Updatable) The number of days offset from the first day of the month, at which the budget processing period starts. In months that have fewer days than this value, processing will begin on the last day of that month. For example, for a value of 12, processing starts every month on the 12th at midnight.
     */
    budgetProcessingPeriodStartOffset?: pulumi.Input<number>;
    /**
     * The OCID of the tenancy
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The description of the budget.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The displayName of the budget.
     */
    displayName?: pulumi.Input<string>;
    /**
     * The forecasted spend in currency by the end of the current budget cycle
     */
    forecastedSpend?: pulumi.Input<number>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The reset period for the budget. Valid value is MONTHLY.
     */
    resetPeriod?: pulumi.Input<string>;
    /**
     * The current state of the budget.
     */
    state?: pulumi.Input<string>;
    /**
     * This is DEPRECTAED. Set the target compartment id in targets instead.
     *
     * @deprecated The 'target_compartment_id' field has been deprecated. Please use 'target_type' instead.
     */
    targetCompartmentId?: pulumi.Input<string>;
    /**
     * The type of target on which the budget is applied.
     */
    targetType?: pulumi.Input<string>;
    /**
     * The list of targets on which the budget is applied. If targetType is "COMPARTMENT", targets contains list of compartment OCIDs. If targetType is "TAG", targets contains list of cost tracking tag identifiers in the form of "{tagNamespace}.{tagKey}.{tagValue}". Curerntly, the array should contain EXACT ONE item.
     */
    targets?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Time that budget was created
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time that the budget spend was last computed
     */
    timeSpendComputed?: pulumi.Input<string>;
    /**
     * Time that budget was updated
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * Version of the budget. Starts from 1 and increments by 1.
     */
    version?: pulumi.Input<number>;
}

/**
 * The set of arguments for constructing a Budget resource.
 */
export interface BudgetArgs {
    /**
     * (Updatable) The amount of the budget expressed as a whole number in the currency of the customer's rate card.
     */
    amount: pulumi.Input<number>;
    /**
     * (Updatable) The number of days offset from the first day of the month, at which the budget processing period starts. In months that have fewer days than this value, processing will begin on the last day of that month. For example, for a value of 12, processing starts every month on the 12th at midnight.
     */
    budgetProcessingPeriodStartOffset?: pulumi.Input<number>;
    /**
     * The OCID of the tenancy
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The description of the budget.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) The displayName of the budget.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The reset period for the budget. Valid value is MONTHLY.
     */
    resetPeriod: pulumi.Input<string>;
    /**
     * This is DEPRECTAED. Set the target compartment id in targets instead.
     *
     * @deprecated The 'target_compartment_id' field has been deprecated. Please use 'target_type' instead.
     */
    targetCompartmentId?: pulumi.Input<string>;
    /**
     * The type of target on which the budget is applied.
     */
    targetType?: pulumi.Input<string>;
    /**
     * The list of targets on which the budget is applied. If targetType is "COMPARTMENT", targets contains list of compartment OCIDs. If targetType is "TAG", targets contains list of cost tracking tag identifiers in the form of "{tagNamespace}.{tagKey}.{tagValue}". Curerntly, the array should contain EXACT ONE item.
     */
    targets?: pulumi.Input<pulumi.Input<string>[]>;
}
