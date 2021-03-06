// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics.Inputs
{

    public sealed class MonitorScriptParameterGetArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// If parameter value is default or overwritten.
        /// </summary>
        [Input("isOverwritten")]
        public Input<bool>? IsOverwritten { get; set; }

        /// <summary>
        /// Describes if  the parameter value is secret and should be kept confidential. isSecret is specified in either CreateScript or UpdateScript API.
        /// </summary>
        [Input("isSecret")]
        public Input<bool>? IsSecret { get; set; }

        /// <summary>
        /// Details of the script parameter that can be used to overwrite the parameter present in the script.
        /// </summary>
        [Input("monitorScriptParameter")]
        public Input<Inputs.MonitorScriptParameterMonitorScriptParameterGetArgs>? MonitorScriptParameter { get; set; }

        /// <summary>
        /// (Updatable) Name of the parameter.
        /// </summary>
        [Input("paramName", required: true)]
        public Input<string> ParamName { get; set; } = null!;

        /// <summary>
        /// (Updatable) Value of the parameter.
        /// </summary>
        [Input("paramValue", required: true)]
        public Input<string> ParamValue { get; set; } = null!;

        public MonitorScriptParameterGetArgs()
        {
        }
    }
}
