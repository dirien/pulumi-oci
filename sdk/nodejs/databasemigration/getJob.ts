// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Job resource in Oracle Cloud Infrastructure Database Migration service.
 *
 * Get a migration job.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testJob = oci.databasemigration.getJob({
 *     jobId: oci_database_migration_job.test_job.id,
 * });
 * ```
 */
export function getJob(args: GetJobArgs, opts?: pulumi.InvokeOptions): Promise<GetJobResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:databasemigration/getJob:getJob", {
        "jobId": args.jobId,
    }, opts);
}

/**
 * A collection of arguments for invoking getJob.
 */
export interface GetJobArgs {
    /**
     * The OCID of the job
     */
    jobId: string;
}

/**
 * A collection of values returned by getJob.
 */
export interface GetJobResult {
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Name of the job.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The OCID of the Migration Job.
     */
    readonly id: string;
    readonly jobId: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * The OCID of the Migration that this job belongs to.
     */
    readonly migrationId: string;
    /**
     * Percent progress of job phase.
     */
    readonly progress: outputs.databasemigration.GetJobProgress;
    /**
     * The current state of the migration job.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time the DB Migration Job was created. An RFC3339 formatted datetime string
     */
    readonly timeCreated: string;
    /**
     * The time the DB Migration Job was last updated. An RFC3339 formatted datetime string
     */
    readonly timeUpdated: string;
    /**
     * Type of unsupported object
     */
    readonly type: string;
    /**
     * Database objects not supported.
     */
    readonly unsupportedObjects: outputs.databasemigration.GetJobUnsupportedObject[];
}
