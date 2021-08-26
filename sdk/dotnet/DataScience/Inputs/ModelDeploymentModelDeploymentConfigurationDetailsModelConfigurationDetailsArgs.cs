// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Inputs
{

    public sealed class ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The network bandwidth for the model.
        /// </summary>
        [Input("bandwidthMbps")]
        public Input<int>? BandwidthMbps { get; set; }

        /// <summary>
        /// (Updatable) The model deployment instance configuration
        /// </summary>
        [Input("instanceConfiguration", required: true)]
        public Input<Inputs.ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsInstanceConfigurationArgs> InstanceConfiguration { get; set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the model you want to deploy.
        /// </summary>
        [Input("modelId", required: true)]
        public Input<string> ModelId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The scaling policy to apply to each model of the deployment.
        /// </summary>
        [Input("scalingPolicy")]
        public Input<Inputs.ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsScalingPolicyArgs>? ScalingPolicy { get; set; }

        public ModelDeploymentModelDeploymentConfigurationDetailsModelConfigurationDetailsArgs()
        {
        }
    }
}
