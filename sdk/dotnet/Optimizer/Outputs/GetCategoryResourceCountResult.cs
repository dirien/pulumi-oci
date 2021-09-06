// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Optimizer.Outputs
{

    [OutputType]
    public sealed class GetCategoryResourceCountResult
    {
        /// <summary>
        /// The count of resources.
        /// </summary>
        public readonly int Count;
        /// <summary>
        /// The recommendation status of the resource.
        /// </summary>
        public readonly string Status;

        [OutputConstructor]
        private GetCategoryResourceCountResult(
            int count,

            string status)
        {
            Count = count;
            Status = status;
        }
    }
}
