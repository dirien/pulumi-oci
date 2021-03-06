// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./backend";
export * from "./backendSet";
export * from "./getBackendHealth";
export * from "./getBackendSet";
export * from "./getBackendSets";
export * from "./getBackends";
export * from "./getListener";
export * from "./getListeners";
export * from "./getNetworkLoadBalancer";
export * from "./getNetworkLoadBalancerHealth";
export * from "./getNetworkLoadBalancers";
export * from "./getNetworkLoadBalancersPolicies";
export * from "./getNetworkLoadBalancersProtocols";
export * from "./listener";
export * from "./networkLoadBalancer";

// Import resources to register:
import { Backend } from "./backend";
import { BackendSet } from "./backendSet";
import { Listener } from "./listener";
import { NetworkLoadBalancer } from "./networkLoadBalancer";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:networkloadbalancer/backend:Backend":
                return new Backend(name, <any>undefined, { urn })
            case "oci:networkloadbalancer/backendSet:BackendSet":
                return new BackendSet(name, <any>undefined, { urn })
            case "oci:networkloadbalancer/listener:Listener":
                return new Listener(name, <any>undefined, { urn })
            case "oci:networkloadbalancer/networkLoadBalancer:NetworkLoadBalancer":
                return new NetworkLoadBalancer(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "networkloadbalancer/backend", _module)
pulumi.runtime.registerResourceModule("oci", "networkloadbalancer/backendSet", _module)
pulumi.runtime.registerResourceModule("oci", "networkloadbalancer/listener", _module)
pulumi.runtime.registerResourceModule("oci", "networkloadbalancer/networkLoadBalancer", _module)
