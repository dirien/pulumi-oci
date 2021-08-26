// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Devops.Inputs
{

    public sealed class DeploymentDeployArtifactOverrideArgumentsItemGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the artifact to which this parameter applies.
        /// </summary>
        [Input("deployArtifactId")]
        public Input<string>? DeployArtifactId { get; set; }

        /// <summary>
        /// Name of the parameter (case-sensitive).
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// value of the argument.
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public DeploymentDeployArtifactOverrideArgumentsItemGetArgs()
        {
        }
    }
}
