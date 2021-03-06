// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Vm Cluster Network Download Config File resource in Oracle Cloud Infrastructure Database service.
 *
 * Downloads the configuration file for the specified VM cluster network. Applies to Exadata Cloud@Customer instances only.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVmClusterNetworkDownloadConfigFile = oci.database.getVmClusterNetworkDownloadConfigFile({
 *     exadataInfrastructureId: oci_database_exadata_infrastructure.test_exadata_infrastructure.id,
 *     vmClusterNetworkId: oci_database_vm_cluster_network.test_vm_cluster_network.id,
 *     base64EncodeContent: "false",
 * });
 * ```
 */
export function getVmClusterNetworkDownloadConfigFile(args: GetVmClusterNetworkDownloadConfigFileArgs, opts?: pulumi.InvokeOptions): Promise<GetVmClusterNetworkDownloadConfigFileResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:database/getVmClusterNetworkDownloadConfigFile:getVmClusterNetworkDownloadConfigFile", {
        "base64EncodeContent": args.base64EncodeContent,
        "exadataInfrastructureId": args.exadataInfrastructureId,
        "vmClusterNetworkId": args.vmClusterNetworkId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVmClusterNetworkDownloadConfigFile.
 */
export interface GetVmClusterNetworkDownloadConfigFileArgs {
    base64EncodeContent?: boolean;
    /**
     * The Exadata infrastructure [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    exadataInfrastructureId: string;
    /**
     * The VM cluster network [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    vmClusterNetworkId: string;
}

/**
 * A collection of values returned by getVmClusterNetworkDownloadConfigFile.
 */
export interface GetVmClusterNetworkDownloadConfigFileResult {
    readonly base64EncodeContent?: boolean;
    /**
     * content of the downloaded config file for exadata infrastructure. If `base64EncodeContent` is set to `true`, then this content will be base64 encoded.
     */
    readonly content: string;
    readonly exadataInfrastructureId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly vmClusterNetworkId: string;
}
