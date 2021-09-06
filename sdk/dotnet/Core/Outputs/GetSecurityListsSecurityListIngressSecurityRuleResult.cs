// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetSecurityListsSecurityListIngressSecurityRuleResult
    {
        /// <summary>
        /// An optional description of your choice for the rule.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Optional and valid only for ICMP and ICMPv6. Use to specify a particular ICMP type and code as defined in:
        /// * [ICMP Parameters](http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
        /// * [ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml)
        /// </summary>
        public readonly Outputs.GetSecurityListsSecurityListIngressSecurityRuleIcmpOptionsResult IcmpOptions;
        /// <summary>
        /// The transport protocol. Specify either `all` or an IPv4 protocol number as defined in [Protocol Numbers](http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Options are supported only for ICMP ("1"), TCP ("6"), UDP ("17"), and ICMPv6 ("58").
        /// </summary>
        public readonly string Protocol;
        /// <summary>
        /// Conceptually, this is the range of IP addresses that a packet coming into the instance can come from.
        /// </summary>
        public readonly string Source;
        /// <summary>
        /// Type of source for the rule. The default is `CIDR_BLOCK`.
        /// * `CIDR_BLOCK`: If the rule's `source` is an IP address range in CIDR notation.
        /// * `SERVICE_CIDR_BLOCK`: If the rule's `source` is the `cidrBlock` value for a [Service](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Service/) (the rule is for traffic coming from a particular `Service` through a service gateway).
        /// </summary>
        public readonly string SourceType;
        /// <summary>
        /// A stateless rule allows traffic in one direction. Remember to add a corresponding stateless rule in the other direction if you need to support bidirectional traffic. For example, if ingress traffic allows TCP destination port 80, there should be an egress rule to allow TCP source port 80. Defaults to false, which means the rule is stateful and a corresponding rule is not necessary for bidirectional traffic.
        /// </summary>
        public readonly bool Stateless;
        /// <summary>
        /// Optional and valid only for TCP. Use to specify particular destination ports for TCP rules. If you specify TCP as the protocol but omit this object, then all destination ports are allowed. 
        /// * The following 2 attributes specify an inclusive range of allowed destination ports. Use the same number for the min and max to indicate a single port. Defaults to all ports if not specified.
        /// </summary>
        public readonly Outputs.GetSecurityListsSecurityListIngressSecurityRuleTcpOptionsResult TcpOptions;
        /// <summary>
        /// Optional and valid only for UDP. Use to specify particular destination ports for UDP rules. If you specify UDP as the protocol but omit this object, then all destination ports are allowed. 
        /// * The following 2 attributes specify an inclusive range of allowed destination ports. Use the same number for the min and max to indicate a single port. Defaults to all ports if not specified.
        /// </summary>
        public readonly Outputs.GetSecurityListsSecurityListIngressSecurityRuleUdpOptionsResult UdpOptions;

        [OutputConstructor]
        private GetSecurityListsSecurityListIngressSecurityRuleResult(
            string description,

            Outputs.GetSecurityListsSecurityListIngressSecurityRuleIcmpOptionsResult icmpOptions,

            string protocol,

            string source,

            string sourceType,

            bool stateless,

            Outputs.GetSecurityListsSecurityListIngressSecurityRuleTcpOptionsResult tcpOptions,

            Outputs.GetSecurityListsSecurityListIngressSecurityRuleUdpOptionsResult udpOptions)
        {
            Description = description;
            IcmpOptions = icmpOptions;
            Protocol = protocol;
            Source = source;
            SourceType = sourceType;
            Stateless = stateless;
            TcpOptions = tcpOptions;
            UdpOptions = udpOptions;
        }
    }
}
