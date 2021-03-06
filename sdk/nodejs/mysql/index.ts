// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./analyticsCluster";
export * from "./channel";
export * from "./getAnalyticsCluster";
export * from "./getChannel";
export * from "./getChannels";
export * from "./getHeatWaveCluster";
export * from "./getMysqlBackup";
export * from "./getMysqlBackups";
export * from "./getMysqlConfiguration";
export * from "./getMysqlConfigurations";
export * from "./getMysqlDbSystem";
export * from "./getMysqlDbSystems";
export * from "./getMysqlVersions";
export * from "./getShapes";
export * from "./heatWaveCluster";
export * from "./mysqlBackup";
export * from "./mysqlDbSystem";

// Import resources to register:
import { AnalyticsCluster } from "./analyticsCluster";
import { Channel } from "./channel";
import { HeatWaveCluster } from "./heatWaveCluster";
import { MysqlBackup } from "./mysqlBackup";
import { MysqlDbSystem } from "./mysqlDbSystem";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:mysql/analyticsCluster:AnalyticsCluster":
                return new AnalyticsCluster(name, <any>undefined, { urn })
            case "oci:mysql/channel:Channel":
                return new Channel(name, <any>undefined, { urn })
            case "oci:mysql/heatWaveCluster:HeatWaveCluster":
                return new HeatWaveCluster(name, <any>undefined, { urn })
            case "oci:mysql/mysqlBackup:MysqlBackup":
                return new MysqlBackup(name, <any>undefined, { urn })
            case "oci:mysql/mysqlDbSystem:MysqlDbSystem":
                return new MysqlDbSystem(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "mysql/analyticsCluster", _module)
pulumi.runtime.registerResourceModule("oci", "mysql/channel", _module)
pulumi.runtime.registerResourceModule("oci", "mysql/heatWaveCluster", _module)
pulumi.runtime.registerResourceModule("oci", "mysql/mysqlBackup", _module)
pulumi.runtime.registerResourceModule("oci", "mysql/mysqlDbSystem", _module)
