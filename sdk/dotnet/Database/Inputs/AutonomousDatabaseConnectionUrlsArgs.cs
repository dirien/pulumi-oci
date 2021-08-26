// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class AutonomousDatabaseConnectionUrlsArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Oracle Application Express (APEX) URL.
        /// </summary>
        [Input("apexUrl")]
        public Input<string>? ApexUrl { get; set; }

        /// <summary>
        /// The URL of the Graph Studio for the Autonomous Database.
        /// </summary>
        [Input("graphStudioUrl")]
        public Input<string>? GraphStudioUrl { get; set; }

        /// <summary>
        /// Oracle Machine Learning user management URL.
        /// </summary>
        [Input("machineLearningUserManagementUrl")]
        public Input<string>? MachineLearningUserManagementUrl { get; set; }

        /// <summary>
        /// Oracle SQL Developer Web URL.
        /// </summary>
        [Input("sqlDevWebUrl")]
        public Input<string>? SqlDevWebUrl { get; set; }

        public AutonomousDatabaseConnectionUrlsArgs()
        {
        }
    }
}
