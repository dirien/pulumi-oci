// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Agent resource in Oracle Cloud Infrastructure Database Migration service.
 *
 * Display the ODMS Agent configuration.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAgent = oci.databasemigration.getAgent({
 *     agentId: oci_database_migration_agent.test_agent.id,
 * });
 * ```
 */
export function getAgent(args: GetAgentArgs, opts?: pulumi.InvokeOptions): Promise<GetAgentResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:databasemigration/getAgent:getAgent", {
        "agentId": args.agentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAgent.
 */
export interface GetAgentArgs {
    /**
     * The OCID of the agent
     */
    agentId: string;
}

/**
 * A collection of values returned by getAgent.
 */
export interface GetAgentResult {
    readonly agentId: string;
    /**
     * OCID of the compartment
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * ODMS Agent name
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The OCID of the resource
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * ODMS Agent public key.
     */
    readonly publicKey: string;
    /**
     * The current state of the ODMS On Prem Agent.
     */
    readonly state: string;
    /**
     * The OCID of the Stream
     */
    readonly streamId: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time the Agent was created. An RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time of the last Agent details update. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
    /**
     * ODMS Agent version
     */
    readonly version: string;
}
