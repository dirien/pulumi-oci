// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Inputs
{

    public sealed class ModelDeploymentCategoryLogDetailsAccessArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a log group to work with.
        /// </summary>
        [Input("logGroupId", required: true)]
        public Input<string> LogGroupId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a log to work with.
        /// </summary>
        [Input("logId", required: true)]
        public Input<string> LogId { get; set; } = null!;

        public ModelDeploymentCategoryLogDetailsAccessArgs()
        {
        }
    }
}