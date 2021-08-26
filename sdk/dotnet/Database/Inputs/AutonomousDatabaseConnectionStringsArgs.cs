// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class AutonomousDatabaseConnectionStringsArgs : Pulumi.ResourceArgs
    {
        [Input("allConnectionStrings")]
        private InputMap<object>? _allConnectionStrings;

        /// <summary>
        /// Returns all connection strings that can be used to connect to the Autonomous Database. For more information, please see [Predefined Database Service Names for Autonomous Transaction Processing](https://docs.oracle.com/en/cloud/paas/atp-cloud/atpug/connect-predefined.html#GUID-9747539B-FD46-44F1-8FF8-F5AC650F15BE)
        /// </summary>
        public InputMap<object> AllConnectionStrings
        {
            get => _allConnectionStrings ?? (_allConnectionStrings = new InputMap<object>());
            set => _allConnectionStrings = value;
        }

        /// <summary>
        /// The database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
        /// </summary>
        [Input("dedicated")]
        public Input<string>? Dedicated { get; set; }

        /// <summary>
        /// The High database service provides the highest level of resources to each SQL statement resulting in the highest performance, but supports the fewest number of concurrent SQL statements.
        /// </summary>
        [Input("high")]
        public Input<string>? High { get; set; }

        /// <summary>
        /// The Low database service provides the least level of resources to each SQL statement, but supports the most number of concurrent SQL statements.
        /// </summary>
        [Input("low")]
        public Input<string>? Low { get; set; }

        /// <summary>
        /// The Medium database service provides a lower level of resources to each SQL statement potentially resulting a lower level of performance, but supports more concurrent SQL statements.
        /// </summary>
        [Input("medium")]
        public Input<string>? Medium { get; set; }

        public AutonomousDatabaseConnectionStringsArgs()
        {
        }
    }
}
