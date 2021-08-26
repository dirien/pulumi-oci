// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiAnomalyDetection.Outputs
{

    [OutputType]
    public sealed class GetModelModelTrainingResultsRowReductionDetailsResult
    {
        /// <summary>
        /// A boolean value to indicate if row reduction is applied
        /// </summary>
        public readonly bool IsReductionEnabled;
        /// <summary>
        /// Method for row reduction:
        /// * DELETE_ROW - delete rows with equal intervals
        /// * AVERAGE_ROW - average multiple rows to one row
        /// </summary>
        public readonly string ReductionMethod;
        /// <summary>
        /// A percentage to reduce data size down to on top of original data
        /// </summary>
        public readonly double ReductionPercentage;

        [OutputConstructor]
        private GetModelModelTrainingResultsRowReductionDetailsResult(
            bool isReductionEnabled,

            string reductionMethod,

            double reductionPercentage)
        {
            IsReductionEnabled = isReductionEnabled;
            ReductionMethod = reductionMethod;
            ReductionPercentage = reductionPercentage;
        }
    }
}
