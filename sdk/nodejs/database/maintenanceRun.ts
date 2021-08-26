// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Maintenance Run resource in Oracle Cloud Infrastructure Database service.
 *
 * Updates the properties of a maintenance run, such as the state of a maintenance run.
 *
 * ## Import
 *
 * MaintenanceRuns can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:database/maintenanceRun:MaintenanceRun test_maintenance_run "id"
 * ```
 */
export class MaintenanceRun extends pulumi.CustomResource {
    /**
     * Get an existing MaintenanceRun resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: MaintenanceRunState, opts?: pulumi.CustomResourceOptions): MaintenanceRun {
        return new MaintenanceRun(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:database/maintenanceRun:MaintenanceRun';

    /**
     * Returns true if the given object is an instance of MaintenanceRun.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is MaintenanceRun {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === MaintenanceRun.__pulumiType;
    }

    /**
     * The OCID of the compartment.
     */
    public /*out*/ readonly compartmentId!: pulumi.Output<string>;
    /**
     * Description of the maintenance run.
     */
    public /*out*/ readonly description!: pulumi.Output<string>;
    /**
     * The user-friendly name for the maintenance run.
     */
    public /*out*/ readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) If `FALSE`, skips the maintenance run.
     */
    public readonly isEnabled!: pulumi.Output<boolean>;
    /**
     * (Updatable) If set to `TRUE`, starts patching immediately.
     */
    public readonly isPatchNowEnabled!: pulumi.Output<boolean>;
    /**
     * Additional information about the current lifecycle state.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * The maintenance run OCID.
     */
    public readonly maintenanceRunId!: pulumi.Output<string>;
    /**
     * Maintenance sub-type.
     */
    public /*out*/ readonly maintenanceSubtype!: pulumi.Output<string>;
    /**
     * Maintenance type.
     */
    public /*out*/ readonly maintenanceType!: pulumi.Output<string>;
    /**
     * Contain the patch failure count.
     */
    public /*out*/ readonly patchFailureCount!: pulumi.Output<number>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the patch to be applied in the maintenance run.
     */
    public readonly patchId!: pulumi.Output<string>;
    /**
     * (Updatable) Cloud Exadata infrastructure node patching method, either "ROLLING" or "NONROLLING". Default value is ROLLING.
     */
    public readonly patchingMode!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance run for the Autonomous Data Guard association's peer container database.
     */
    public /*out*/ readonly peerMaintenanceRunId!: pulumi.Output<string>;
    /**
     * The current state of the maintenance run. For Autonomous Database on shared Exadata infrastructure, valid states are IN_PROGRESS, SUCCEEDED and FAILED.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The ID of the target resource on which the maintenance run occurs.
     */
    public /*out*/ readonly targetResourceId!: pulumi.Output<string>;
    /**
     * The type of the target resource on which the maintenance run occurs.
     */
    public /*out*/ readonly targetResourceType!: pulumi.Output<string>;
    /**
     * The date and time the maintenance run was completed.
     */
    public /*out*/ readonly timeEnded!: pulumi.Output<string>;
    /**
     * (Updatable) The scheduled date and time of the maintenance run to update.
     */
    public readonly timeScheduled!: pulumi.Output<string>;
    /**
     * The date and time the maintenance run starts.
     */
    public /*out*/ readonly timeStarted!: pulumi.Output<string>;

    /**
     * Create a MaintenanceRun resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: MaintenanceRunArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: MaintenanceRunArgs | MaintenanceRunState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as MaintenanceRunState | undefined;
            inputs["compartmentId"] = state ? state.compartmentId : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["isEnabled"] = state ? state.isEnabled : undefined;
            inputs["isPatchNowEnabled"] = state ? state.isPatchNowEnabled : undefined;
            inputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            inputs["maintenanceRunId"] = state ? state.maintenanceRunId : undefined;
            inputs["maintenanceSubtype"] = state ? state.maintenanceSubtype : undefined;
            inputs["maintenanceType"] = state ? state.maintenanceType : undefined;
            inputs["patchFailureCount"] = state ? state.patchFailureCount : undefined;
            inputs["patchId"] = state ? state.patchId : undefined;
            inputs["patchingMode"] = state ? state.patchingMode : undefined;
            inputs["peerMaintenanceRunId"] = state ? state.peerMaintenanceRunId : undefined;
            inputs["state"] = state ? state.state : undefined;
            inputs["targetResourceId"] = state ? state.targetResourceId : undefined;
            inputs["targetResourceType"] = state ? state.targetResourceType : undefined;
            inputs["timeEnded"] = state ? state.timeEnded : undefined;
            inputs["timeScheduled"] = state ? state.timeScheduled : undefined;
            inputs["timeStarted"] = state ? state.timeStarted : undefined;
        } else {
            const args = argsOrState as MaintenanceRunArgs | undefined;
            if ((!args || args.maintenanceRunId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'maintenanceRunId'");
            }
            inputs["isEnabled"] = args ? args.isEnabled : undefined;
            inputs["isPatchNowEnabled"] = args ? args.isPatchNowEnabled : undefined;
            inputs["maintenanceRunId"] = args ? args.maintenanceRunId : undefined;
            inputs["patchId"] = args ? args.patchId : undefined;
            inputs["patchingMode"] = args ? args.patchingMode : undefined;
            inputs["timeScheduled"] = args ? args.timeScheduled : undefined;
            inputs["compartmentId"] = undefined /*out*/;
            inputs["description"] = undefined /*out*/;
            inputs["displayName"] = undefined /*out*/;
            inputs["lifecycleDetails"] = undefined /*out*/;
            inputs["maintenanceSubtype"] = undefined /*out*/;
            inputs["maintenanceType"] = undefined /*out*/;
            inputs["patchFailureCount"] = undefined /*out*/;
            inputs["peerMaintenanceRunId"] = undefined /*out*/;
            inputs["state"] = undefined /*out*/;
            inputs["targetResourceId"] = undefined /*out*/;
            inputs["targetResourceType"] = undefined /*out*/;
            inputs["timeEnded"] = undefined /*out*/;
            inputs["timeStarted"] = undefined /*out*/;
        }
        if (!opts.version) {
            opts = pulumi.mergeOptions(opts, { version: utilities.getVersion()});
        }
        super(MaintenanceRun.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering MaintenanceRun resources.
 */
export interface MaintenanceRunState {
    /**
     * The OCID of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Description of the maintenance run.
     */
    description?: pulumi.Input<string>;
    /**
     * The user-friendly name for the maintenance run.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) If `FALSE`, skips the maintenance run.
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) If set to `TRUE`, starts patching immediately.
     */
    isPatchNowEnabled?: pulumi.Input<boolean>;
    /**
     * Additional information about the current lifecycle state.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * The maintenance run OCID.
     */
    maintenanceRunId?: pulumi.Input<string>;
    /**
     * Maintenance sub-type.
     */
    maintenanceSubtype?: pulumi.Input<string>;
    /**
     * Maintenance type.
     */
    maintenanceType?: pulumi.Input<string>;
    /**
     * Contain the patch failure count.
     */
    patchFailureCount?: pulumi.Input<number>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the patch to be applied in the maintenance run.
     */
    patchId?: pulumi.Input<string>;
    /**
     * (Updatable) Cloud Exadata infrastructure node patching method, either "ROLLING" or "NONROLLING". Default value is ROLLING.
     */
    patchingMode?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the maintenance run for the Autonomous Data Guard association's peer container database.
     */
    peerMaintenanceRunId?: pulumi.Input<string>;
    /**
     * The current state of the maintenance run. For Autonomous Database on shared Exadata infrastructure, valid states are IN_PROGRESS, SUCCEEDED and FAILED.
     */
    state?: pulumi.Input<string>;
    /**
     * The ID of the target resource on which the maintenance run occurs.
     */
    targetResourceId?: pulumi.Input<string>;
    /**
     * The type of the target resource on which the maintenance run occurs.
     */
    targetResourceType?: pulumi.Input<string>;
    /**
     * The date and time the maintenance run was completed.
     */
    timeEnded?: pulumi.Input<string>;
    /**
     * (Updatable) The scheduled date and time of the maintenance run to update.
     */
    timeScheduled?: pulumi.Input<string>;
    /**
     * The date and time the maintenance run starts.
     */
    timeStarted?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a MaintenanceRun resource.
 */
export interface MaintenanceRunArgs {
    /**
     * (Updatable) If `FALSE`, skips the maintenance run.
     */
    isEnabled?: pulumi.Input<boolean>;
    /**
     * (Updatable) If set to `TRUE`, starts patching immediately.
     */
    isPatchNowEnabled?: pulumi.Input<boolean>;
    /**
     * The maintenance run OCID.
     */
    maintenanceRunId: pulumi.Input<string>;
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the patch to be applied in the maintenance run.
     */
    patchId?: pulumi.Input<string>;
    /**
     * (Updatable) Cloud Exadata infrastructure node patching method, either "ROLLING" or "NONROLLING". Default value is ROLLING.
     */
    patchingMode?: pulumi.Input<string>;
    /**
     * (Updatable) The scheduled date and time of the maintenance run to update.
     */
    timeScheduled?: pulumi.Input<string>;
}
