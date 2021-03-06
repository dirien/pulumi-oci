// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Management Agent Install Key resource in Oracle Cloud Infrastructure Management Agent service.
 *
 * Gets complete details of the Agent install Key for a given key id
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagementAgentInstallKey = oci.managementagent.getManagementAgentInstallKey({
 *     managementAgentInstallKeyId: oci_management_agent_management_agent_install_key.test_management_agent_install_key.id,
 * });
 * ```
 */
export function getManagementAgentInstallKey(args: GetManagementAgentInstallKeyArgs, opts?: pulumi.InvokeOptions): Promise<GetManagementAgentInstallKeyResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:managementagent/getManagementAgentInstallKey:getManagementAgentInstallKey", {
        "managementAgentInstallKeyId": args.managementAgentInstallKeyId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagementAgentInstallKey.
 */
export interface GetManagementAgentInstallKeyArgs {
    /**
     * Unique Management Agent Install Key identifier
     */
    managementAgentInstallKeyId: string;
}

/**
 * A collection of values returned by getManagementAgentInstallKey.
 */
export interface GetManagementAgentInstallKeyResult {
    /**
     * Total number of install for this keys
     */
    readonly allowedKeyInstallCount: number;
    /**
     * Compartment Identifier
     */
    readonly compartmentId: string;
    /**
     * Principal id of user who created the Agent Install key
     */
    readonly createdByPrincipalId: string;
    /**
     * Total number of install for this keys
     */
    readonly currentKeyInstallCount: number;
    /**
     * Management Agent Install Key Name
     */
    readonly displayName: string;
    /**
     * Agent install Key identifier
     */
    readonly id: string;
    /**
     * Management Agent Install Key
     */
    readonly key: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
     */
    readonly lifecycleDetails: string;
    readonly managementAgentInstallKeyId: string;
    /**
     * Status of Key
     */
    readonly state: string;
    /**
     * The time when Management Agent install Key was created. An RFC3339 formatted date time string
     */
    readonly timeCreated: string;
    /**
     * date after which key would expire after creation
     */
    readonly timeExpires: string;
    /**
     * The time when Management Agent install Key was updated. An RFC3339 formatted date time string
     */
    readonly timeUpdated: string;
}
