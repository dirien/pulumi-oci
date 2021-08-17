// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "./types";
import * as utilities from "./utilities";

/**
 * This data source provides the list of Autonomous Exadata Infrastructures in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of the Autonomous Exadata Infrastructures in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousExadataInfrastructures = oci.GetDatabaseAutonomousExadataInfrastructures({
 *     compartmentId: _var.compartment_id,
 *     availabilityDomain: _var.autonomous_exadata_infrastructure_availability_domain,
 *     displayName: _var.autonomous_exadata_infrastructure_display_name,
 *     state: _var.autonomous_exadata_infrastructure_state,
 * });
 * ```
 */
export function getDatabaseAutonomousExadataInfrastructures(args: GetDatabaseAutonomousExadataInfrastructuresArgs, opts?: pulumi.InvokeOptions): Promise<GetDatabaseAutonomousExadataInfrastructuresResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:index/getDatabaseAutonomousExadataInfrastructures:GetDatabaseAutonomousExadataInfrastructures", {
        "availabilityDomain": args.availabilityDomain,
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking GetDatabaseAutonomousExadataInfrastructures.
 */
export interface GetDatabaseAutonomousExadataInfrastructuresArgs {
    /**
     * A filter to return only resources that match the given availability domain exactly.
     */
    availabilityDomain?: string;
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given. The match is not case sensitive.
     */
    displayName?: string;
    filters?: inputs.GetDatabaseAutonomousExadataInfrastructuresFilter[];
    /**
     * A filter to return only resources that match the given lifecycle state exactly.
     */
    state?: string;
}

/**
 * A collection of values returned by GetDatabaseAutonomousExadataInfrastructures.
 */
export interface GetDatabaseAutonomousExadataInfrastructuresResult {
    /**
     * The list of autonomous_exadata_infrastructures.
     */
    readonly autonomousExadataInfrastructures: outputs.GetDatabaseAutonomousExadataInfrastructuresAutonomousExadataInfrastructure[];
    /**
     * The name of the availability domain that the Autonomous Exadata Infrastructure is located in.
     */
    readonly availabilityDomain?: string;
    /**
     * The OCID of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The user-friendly name for the Autonomous Exadata Infrastructure.
     */
    readonly displayName?: string;
    readonly filters?: outputs.GetDatabaseAutonomousExadataInfrastructuresFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current lifecycle state of the Autonomous Exadata Infrastructure.
     */
    readonly state?: string;
}