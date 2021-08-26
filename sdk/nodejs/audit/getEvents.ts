// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Audit Events in Oracle Cloud Infrastructure Audit service.
 *
 * Returns all the audit events processed for the specified compartment within the specified
 * time range.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAuditEvents = oci.audit.getEvents({
 *     compartmentId: _var.compartment_id,
 *     endTime: _var.audit_event_end_time,
 *     startTime: _var.audit_event_start_time,
 * });
 * ```
 */
export function getEvents(args: GetEventsArgs, opts?: pulumi.InvokeOptions): Promise<GetEventsResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:audit/getEvents:getEvents", {
        "compartmentId": args.compartmentId,
        "endTime": args.endTime,
        "filters": args.filters,
        "startTime": args.startTime,
    }, opts);
}

/**
 * A collection of arguments for invoking getEvents.
 */
export interface GetEventsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * Returns events that were processed before this end date and time, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     */
    endTime: string;
    filters?: inputs.audit.GetEventsFilter[];
    /**
     * Returns events that were processed at or after this start date and time, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
     */
    startTime: string;
}

/**
 * A collection of values returned by getEvents.
 */
export interface GetEventsResult {
    /**
     * The list of audit_events.
     */
    readonly auditEvents: outputs.audit.GetEventsAuditEvent[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment of the resource  emitting the event.
     */
    readonly compartmentId: string;
    readonly endTime: string;
    readonly filters?: outputs.audit.GetEventsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly startTime: string;
}