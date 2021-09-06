// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Inputs
{

    public sealed class RuleSetItemConditionArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The attribute_name can be one of these values: `PATH`, `SOURCE_IP_ADDRESS`, `SOURCE_VCN_ID`, `SOURCE_VCN_IP_ADDRESS`
        /// </summary>
        [Input("attributeName", required: true)]
        public Input<string> AttributeName { get; set; } = null!;

        /// <summary>
        /// (Updatable) Depends on `attribute_name`:
        /// - when `attribute_name` = `SOURCE_IP_ADDRESS` | IPv4 or IPv6 address range to which the source IP address of incoming packet would be matched against
        /// - when `attribute_name` = `SOURCE_VCN_IP_ADDRESS` | IPv4 address range to which the original client IP address (in customer VCN) of incoming packet would be matched against
        /// - when `attribute_name` = `SOURCE_VCN_ID` | OCID of the customer VCN to which the service gateway embedded VCN ID of incoming packet would be matched against
        /// </summary>
        [Input("attributeValue", required: true)]
        public Input<string> AttributeValue { get; set; } = null!;

        /// <summary>
        /// (Updatable) A string that specifies how to compare the PathMatchCondition object's `attributeValue` string to the incoming URI.
        /// *  **EXACT_MATCH** - The incoming URI path must exactly and completely match the `attributeValue` string.
        /// *  **FORCE_LONGEST_PREFIX_MATCH** - The system looks for the `attributeValue` string with the best, longest match of the beginning portion of the incoming URI path.
        /// *  **PREFIX_MATCH** - The beginning portion of the incoming URI path must exactly match the `attributeValue` string.
        /// *  **SUFFIX_MATCH** - The ending portion of the incoming URI path must exactly match the `attributeValue` string.
        /// </summary>
        [Input("operator")]
        public Input<string>? Operator { get; set; }

        public RuleSetItemConditionArgs()
        {
        }
    }
}
