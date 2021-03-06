// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Devops.Inputs
{

    public sealed class DeployStageWaitCriteriaGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The absolute wait duration. An ISO 8601 formatted duration string. Minimum waitDuration should be 5 seconds. Maximum waitDuration can be up to 2 days.
        /// </summary>
        [Input("waitDuration", required: true)]
        public Input<string> WaitDuration { get; set; } = null!;

        /// <summary>
        /// (Updatable) Wait criteria type.
        /// </summary>
        [Input("waitType", required: true)]
        public Input<string> WaitType { get; set; } = null!;

        public DeployStageWaitCriteriaGetArgs()
        {
        }
    }
}
