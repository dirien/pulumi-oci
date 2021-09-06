// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Devops.Outputs
{

    [OutputType]
    public sealed class GetDeployStageWaitCriteriaResult
    {
        /// <summary>
        /// The absolute wait duration. An ISO 8601 formatted duration string. Minimum waitDuration should be 5 seconds. Maximum waitDuration can be up to 2 days.
        /// </summary>
        public readonly string WaitDuration;
        /// <summary>
        /// Wait criteria type.
        /// </summary>
        public readonly string WaitType;

        [OutputConstructor]
        private GetDeployStageWaitCriteriaResult(
            string waitDuration,

            string waitType)
        {
            WaitDuration = waitDuration;
            WaitType = waitType;
        }
    }
}
