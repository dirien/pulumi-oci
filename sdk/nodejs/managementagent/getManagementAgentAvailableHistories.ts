// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Management Agent Available Histories in Oracle Cloud Infrastructure Management Agent service.
 *
 * Lists the availability history records of Management Agent
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagementAgentAvailableHistories = oci.managementagent.getManagementAgentAvailableHistories({
 *     managementAgentId: oci_management_agent_management_agent.test_management_agent.id,
 *     timeAvailabilityStatusEndedGreaterThan: _var.management_agent_available_history_time_availability_status_ended_greater_than,
 *     timeAvailabilityStatusStartedLessThan: _var.management_agent_available_history_time_availability_status_started_less_than,
 * });
 * ```
 */
export function getManagementAgentAvailableHistories(args: GetManagementAgentAvailableHistoriesArgs, opts?: pulumi.InvokeOptions): Promise<GetManagementAgentAvailableHistoriesResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:managementagent/getManagementAgentAvailableHistories:getManagementAgentAvailableHistories", {
        "filters": args.filters,
        "managementAgentId": args.managementAgentId,
        "timeAvailabilityStatusEndedGreaterThan": args.timeAvailabilityStatusEndedGreaterThan,
        "timeAvailabilityStatusStartedLessThan": args.timeAvailabilityStatusStartedLessThan,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagementAgentAvailableHistories.
 */
export interface GetManagementAgentAvailableHistoriesArgs {
    filters?: inputs.managementagent.GetManagementAgentAvailableHistoriesFilter[];
    /**
     * Unique Management Agent identifier
     */
    managementAgentId: string;
    /**
     * Filter to limit the availability history results to that of time after the input time including the boundary record. Defaulted to current date minus one year. The date and time to be given as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     */
    timeAvailabilityStatusEndedGreaterThan?: string;
    /**
     * Filter to limit the availability history results to that of time before the input time including the boundary record Defaulted to current date. The date and time to be given as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     */
    timeAvailabilityStatusStartedLessThan?: string;
}

/**
 * A collection of values returned by getManagementAgentAvailableHistories.
 */
export interface GetManagementAgentAvailableHistoriesResult {
    /**
     * The list of availability_histories.
     */
    readonly availabilityHistories: outputs.managementagent.GetManagementAgentAvailableHistoriesAvailabilityHistory[];
    readonly filters?: outputs.managementagent.GetManagementAgentAvailableHistoriesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * agent identifier
     */
    readonly managementAgentId: string;
    readonly timeAvailabilityStatusEndedGreaterThan?: string;
    readonly timeAvailabilityStatusStartedLessThan?: string;
}
