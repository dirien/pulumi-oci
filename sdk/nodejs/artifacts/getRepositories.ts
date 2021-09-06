// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Repositories in Oracle Cloud Infrastructure Artifacts service.
 *
 * Lists repositories in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRepositories = oci.artifacts.getRepositories({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.repository_display_name,
 *     id: _var.repository_id,
 *     isImmutable: _var.repository_is_immutable,
 *     state: _var.repository_state,
 * });
 * ```
 */
export function getRepositories(args: GetRepositoriesArgs, opts?: pulumi.InvokeOptions): Promise<GetRepositoriesResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:artifacts/getRepositories:getRepositories", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "isImmutable": args.isImmutable,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getRepositories.
 */
export interface GetRepositoriesArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the given display name exactly.
     */
    displayName?: string;
    filters?: inputs.artifacts.GetRepositoriesFilter[];
    /**
     * A filter to return the resources for the specified OCID.
     */
    id?: string;
    /**
     * A filter to return resources that match the isImmutable value.
     */
    isImmutable?: boolean;
    /**
     * A filter to return only resources that match the given lifecycle state name exactly.
     */
    state?: string;
}

/**
 * A collection of values returned by getRepositories.
 */
export interface GetRepositoriesResult {
    /**
     * The OCID of the repository's compartment.
     */
    readonly compartmentId: string;
    /**
     * The repository name.
     */
    readonly displayName?: string;
    readonly filters?: outputs.artifacts.GetRepositoriesFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository.  Example: `ocid1.artifactrepository.oc1..exampleuniqueID`
     */
    readonly id?: string;
    /**
     * Whether the repository is immutable. The artifacts of an immutable repository cannot be overwritten.
     */
    readonly isImmutable?: boolean;
    /**
     * The list of repository_collection.
     */
    readonly repositoryCollections: outputs.artifacts.GetRepositoriesRepositoryCollection[];
    /**
     * The current state of the repository.
     */
    readonly state?: string;
}
