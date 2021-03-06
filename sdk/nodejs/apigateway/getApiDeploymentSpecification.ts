// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Api Deployment Specification resource in Oracle Cloud Infrastructure API Gateway service.
 *
 * Gets an API Deployment specification by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testApiDeploymentSpecification = oci.apigateway.getApiDeploymentSpecification({
 *     apiId: oci_apigateway_api.test_api.id,
 * });
 * ```
 */
export function getApiDeploymentSpecification(args: GetApiDeploymentSpecificationArgs, opts?: pulumi.InvokeOptions): Promise<GetApiDeploymentSpecificationResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("oci:apigateway/getApiDeploymentSpecification:getApiDeploymentSpecification", {
        "apiId": args.apiId,
    }, opts);
}

/**
 * A collection of arguments for invoking getApiDeploymentSpecification.
 */
export interface GetApiDeploymentSpecificationArgs {
    /**
     * The ocid of the API.
     */
    apiId: string;
}

/**
 * A collection of values returned by getApiDeploymentSpecification.
 */
export interface GetApiDeploymentSpecificationResult {
    readonly apiId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Policies controlling the pushing of logs to Oracle Cloud Infrastructure Public Logging.
     */
    readonly loggingPolicies: outputs.apigateway.GetApiDeploymentSpecificationLoggingPolicy[];
    /**
     * Behavior applied to any requests received by the API on this route.
     */
    readonly requestPolicies: outputs.apigateway.GetApiDeploymentSpecificationRequestPolicy[];
    /**
     * A list of routes that this API exposes.
     */
    readonly routes: outputs.apigateway.GetApiDeploymentSpecificationRoute[];
}
