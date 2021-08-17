// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Outputs
{

    [OutputType]
    public sealed class GetMonitoringMetricDataMetricDataAggregatedDatapointResult
    {
        /// <summary>
        /// The date and time associated with the value of this data point. Format defined by RFC3339.  Example: `2019-02-01T01:02:29.600Z`
        /// </summary>
        public readonly string Timestamp;
        /// <summary>
        /// Numeric value of the metric.  Example: `10.4`
        /// </summary>
        public readonly double Value;

        [OutputConstructor]
        private GetMonitoringMetricDataMetricDataAggregatedDatapointResult(
            string timestamp,

            double value)
        {
            Timestamp = timestamp;
            Value = value;
        }
    }
}