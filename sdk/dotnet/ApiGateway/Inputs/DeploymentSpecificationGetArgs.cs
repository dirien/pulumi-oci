// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Policies controlling the pushing of logs to Oracle Cloud Infrastructure Public Logging.
        /// </summary>
        [Input("loggingPolicies")]
        public Input<Inputs.DeploymentSpecificationLoggingPoliciesGetArgs>? LoggingPolicies { get; set; }

        /// <summary>
        /// (Updatable) Behavior applied to any requests received by the API on this route.
        /// </summary>
        [Input("requestPolicies")]
        public Input<Inputs.DeploymentSpecificationRequestPoliciesGetArgs>? RequestPolicies { get; set; }

        [Input("routes", required: true)]
        private InputList<Inputs.DeploymentSpecificationRouteGetArgs>? _routes;

        /// <summary>
        /// (Updatable) A list of routes that this API exposes.
        /// </summary>
        public InputList<Inputs.DeploymentSpecificationRouteGetArgs> Routes
        {
            get => _routes ?? (_routes = new InputList<Inputs.DeploymentSpecificationRouteGetArgs>());
            set => _routes = value;
        }

        public DeploymentSpecificationGetArgs()
        {
        }
    }
}
