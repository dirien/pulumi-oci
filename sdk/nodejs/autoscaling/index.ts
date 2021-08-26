// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./autoScalingConfiguration";
export * from "./getAutoScalingConfiguration";
export * from "./getAutoScalingConfigurations";

// Import resources to register:
import { AutoScalingConfiguration } from "./autoScalingConfiguration";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:autoscaling/autoScalingConfiguration:AutoScalingConfiguration":
                return new AutoScalingConfiguration(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "autoscaling/autoScalingConfiguration", _module)
