// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Deployment Backup resource in Oracle Cloud Infrastructure Golden Gate service.
 *
 * Retrieves a DeploymentBackup.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDeploymentBackup = oci.goldengate.getDeploymentBackup({
 *     deploymentBackupId: oci_golden_gate_deployment_backup.test_deployment_backup.id,
 * });
 * ```
 */
export function getDeploymentBackup(args: GetDeploymentBackupArgs, opts?: pulumi.InvokeOptions): Promise<GetDeploymentBackupResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:goldengate/getDeploymentBackup:getDeploymentBackup", {
        "deploymentBackupId": args.deploymentBackupId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDeploymentBackup.
 */
export interface GetDeploymentBackupArgs {
    /**
     * A unique DeploymentBackup identifier.
     */
    deploymentBackupId: string;
}

/**
 * A collection of values returned by getDeploymentBackup.
 */
export interface GetDeploymentBackupResult {
    /**
     * Possible Deployment backup types.
     */
    readonly backupType: string;
    /**
     * Name of the bucket where the object is to be uploaded in the object storage
     */
    readonly bucket: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
     */
    readonly compartmentId: string;
    /**
     * Tags defined for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    readonly deploymentBackupId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
     */
    readonly deploymentId: string;
    /**
     * An object's Display Name.
     */
    readonly displayName: string;
    /**
     * A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup being referenced.
     */
    readonly id: string;
    /**
     * True if this object is automatically created
     */
    readonly isAutomatic: boolean;
    /**
     * Describes the object's current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * Name of namespace that serves as a container for all of your buckets
     */
    readonly namespace: string;
    /**
     * Name of the object to be uploaded to object storage
     */
    readonly object: string;
    /**
     * Version of OGG
     */
    readonly oggVersion: string;
    /**
     * Possible lifecycle states.
     */
    readonly state: string;
    /**
     * The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     */
    readonly timeCreated: string;
    /**
     * The time of the resource backup. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     */
    readonly timeOfBackup: string;
    /**
     * The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     */
    readonly timeUpdated: string;
}
