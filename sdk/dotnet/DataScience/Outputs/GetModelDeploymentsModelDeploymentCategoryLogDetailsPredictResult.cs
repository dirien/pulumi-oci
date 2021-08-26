// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class GetModelDeploymentsModelDeploymentCategoryLogDetailsPredictResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a log group to work with.
        /// </summary>
        public readonly string LogGroupId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a log to work with.
        /// </summary>
        public readonly string LogId;

        [OutputConstructor]
        private GetModelDeploymentsModelDeploymentCategoryLogDetailsPredictResult(
            string logGroupId,

            string logId)
        {
            LogGroupId = logGroupId;
            LogId = logId;
        }
    }
}
