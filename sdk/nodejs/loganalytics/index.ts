// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./getLogAnalyticsEntities";
export * from "./getLogAnalyticsEntitiesSummary";
export * from "./getLogAnalyticsEntity";
export * from "./getLogAnalyticsLogGroup";
export * from "./getLogAnalyticsLogGroups";
export * from "./getLogAnalyticsLogGroupsSummary";
export * from "./getLogAnalyticsObjectCollectionRule";
export * from "./getLogAnalyticsObjectCollectionRules";
export * from "./getNamespace";
export * from "./getNamespaces";
export * from "./logAnalyticsEntity";
export * from "./logAnalyticsLogGroup";
export * from "./logAnalyticsObjectCollectionRule";
export * from "./namespace";

// Import resources to register:
import { LogAnalyticsEntity } from "./logAnalyticsEntity";
import { LogAnalyticsLogGroup } from "./logAnalyticsLogGroup";
import { LogAnalyticsObjectCollectionRule } from "./logAnalyticsObjectCollectionRule";
import { Namespace } from "./namespace";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:loganalytics/logAnalyticsEntity:LogAnalyticsEntity":
                return new LogAnalyticsEntity(name, <any>undefined, { urn })
            case "oci:loganalytics/logAnalyticsLogGroup:LogAnalyticsLogGroup":
                return new LogAnalyticsLogGroup(name, <any>undefined, { urn })
            case "oci:loganalytics/logAnalyticsObjectCollectionRule:LogAnalyticsObjectCollectionRule":
                return new LogAnalyticsObjectCollectionRule(name, <any>undefined, { urn })
            case "oci:loganalytics/namespace:Namespace":
                return new Namespace(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "loganalytics/logAnalyticsEntity", _module)
pulumi.runtime.registerResourceModule("oci", "loganalytics/logAnalyticsLogGroup", _module)
pulumi.runtime.registerResourceModule("oci", "loganalytics/logAnalyticsObjectCollectionRule", _module)
pulumi.runtime.registerResourceModule("oci", "loganalytics/namespace", _module)
