// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

// Export members:
export * from "./getModel";
export * from "./getModelDeployment";
export * from "./getModelDeploymentShapes";
export * from "./getModelDeployments";
export * from "./getModelProvenance";
export * from "./getModels";
export * from "./getNotebookSession";
export * from "./getNotebookSessionShapes";
export * from "./getNotebookSessions";
export * from "./getProject";
export * from "./getProjects";
export * from "./model";
export * from "./modelDeployment";
export * from "./modelProvenance";
export * from "./notebookSession";
export * from "./project";

// Import resources to register:
import { Model } from "./model";
import { ModelDeployment } from "./modelDeployment";
import { ModelProvenance } from "./modelProvenance";
import { NotebookSession } from "./notebookSession";
import { Project } from "./project";

const _module = {
    version: utilities.getVersion(),
    construct: (name: string, type: string, urn: string): pulumi.Resource => {
        switch (type) {
            case "oci:datascience/model:Model":
                return new Model(name, <any>undefined, { urn })
            case "oci:datascience/modelDeployment:ModelDeployment":
                return new ModelDeployment(name, <any>undefined, { urn })
            case "oci:datascience/modelProvenance:ModelProvenance":
                return new ModelProvenance(name, <any>undefined, { urn })
            case "oci:datascience/notebookSession:NotebookSession":
                return new NotebookSession(name, <any>undefined, { urn })
            case "oci:datascience/project:Project":
                return new Project(name, <any>undefined, { urn })
            default:
                throw new Error(`unknown resource type ${type}`);
        }
    },
};
pulumi.runtime.registerResourceModule("oci", "datascience/model", _module)
pulumi.runtime.registerResourceModule("oci", "datascience/modelDeployment", _module)
pulumi.runtime.registerResourceModule("oci", "datascience/modelProvenance", _module)
pulumi.runtime.registerResourceModule("oci", "datascience/notebookSession", _module)
pulumi.runtime.registerResourceModule("oci", "datascience/project", _module)
