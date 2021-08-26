// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Private Endpoint resource in Oracle Cloud Infrastructure Data Flow service.
 *
 * Retrieves an private endpoint using a `privateEndpointId`.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testPrivateEndpoint = oci.dataflow.getPrivateEndpoint({
 *     privateEndpointId: oci_dataflow_private_endpoint.test_private_endpoint.id,
 * });
 * ```
 */
export function getPrivateEndpoint(args: GetPrivateEndpointArgs, opts?: pulumi.InvokeOptions): Promise<GetPrivateEndpointResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:dataflow/getPrivateEndpoint:getPrivateEndpoint", {
        "privateEndpointId": args.privateEndpointId,
    }, opts);
}

/**
 * A collection of arguments for invoking getPrivateEndpoint.
 */
export interface GetPrivateEndpointArgs {
    /**
     * The unique ID for a private endpoint.
     */
    privateEndpointId: string;
}

/**
 * A collection of values returned by getPrivateEndpoint.
 */
export interface GetPrivateEndpointResult {
    /**
     * The OCID of a compartment.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * A user-friendly description. Avoid entering confidential information.
     */
    readonly description: string;
    /**
     * A user-friendly name. It does not have to be unique. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * An array of DNS zone names. Example: `[ "app.examplecorp.com", "app.examplecorp2.com" ]`
     */
    readonly dnsZones: string[];
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The OCID of a private endpoint.
     */
    readonly id: string;
    /**
     * The detailed messages about the lifecycle state.
     */
    readonly lifecycleDetails: string;
    /**
     * The maximum number of hosts to be accessed through the private endpoint. This value is used to calculate the relevant CIDR block and should be a multiple of 256.  If the value is not a multiple of 256, it is rounded up to the next multiple of 256. For example, 300 is rounded up to 512.
     */
    readonly maxHostCount: number;
    /**
     * An array of network security group OCIDs.
     */
    readonly nsgIds: string[];
    /**
     * The OCID of the user who created the resource.
     */
    readonly ownerPrincipalId: string;
    /**
     * The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
     */
    readonly ownerUserName: string;
    readonly privateEndpointId: string;
    /**
     * The current state of this private endpoint.
     */
    readonly state: string;
    /**
     * The OCID of a subnet.
     */
    readonly subnetId: string;
    /**
     * The date and time a application was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    readonly timeCreated: string;
    /**
     * The date and time a application was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
     */
    readonly timeUpdated: string;
}
