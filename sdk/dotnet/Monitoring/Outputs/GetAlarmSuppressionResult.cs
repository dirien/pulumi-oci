// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Monitoring.Outputs
{

    [OutputType]
    public sealed class GetAlarmSuppressionResult
    {
        /// <summary>
        /// Human-readable reason for suppressing alarm notifications. It does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The start date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2019-02-01T01:02:29.600Z`
        /// </summary>
        public readonly string TimeSuppressFrom;
        /// <summary>
        /// The end date and time for the suppression to take place, inclusive. Format defined by RFC3339.  Example: `2019-02-01T02:02:29.600Z`
        /// </summary>
        public readonly string TimeSuppressUntil;

        [OutputConstructor]
        private GetAlarmSuppressionResult(
            string description,

            string timeSuppressFrom,

            string timeSuppressUntil)
        {
            Description = description;
            TimeSuppressFrom = timeSuppressFrom;
            TimeSuppressUntil = timeSuppressUntil;
        }
    }
}
