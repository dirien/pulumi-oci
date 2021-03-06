// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Deployment resource in Oracle Cloud Infrastructure API Gateway service.
 *
 * Gets a deployment by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDeployment = oci.apigateway.getDeployment({
 *     deploymentId: oci_apigateway_deployment.test_deployment.id,
 * });
 * ```
 */
export function getDeployment(args: GetDeploymentArgs, opts?: pulumi.InvokeOptions): Promise<GetDeploymentResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:apigateway/getDeployment:getDeployment", {
        "deploymentId": args.deploymentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDeployment.
 */
export interface GetDeploymentArgs {
    /**
     * The ocid of the deployment.
     */
    deploymentId: string;
}

/**
 * A collection of values returned by getDeployment.
 */
export interface GetDeploymentResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    readonly deploymentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    readonly displayName: string;
    /**
     * The endpoint to access this deployment on the gateway.
     */
    readonly endpoint: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     */
    readonly gatewayId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * A path on which to deploy all routes contained in the API deployment specification. For more information, see [Deploying an API on an API Gateway by Creating an API Deployment](https://docs.cloud.oracle.com/iaas/Content/APIGateway/Tasks/apigatewaycreatingdeployment.htm).
     */
    readonly pathPrefix: string;
    /**
     * The logical configuration of the API exposed by a deployment.
     */
    readonly specification: outputs.apigateway.GetDeploymentSpecification;
    /**
     * The current state of the deployment.
     */
    readonly state: string;
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
}
