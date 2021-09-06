// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package events

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Rule resource in Oracle Cloud Infrastructure Events service.
//
// Retrieves a rule.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/events"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := events.LookupRule(ctx, &events.LookupRuleArgs{
// 			RuleId: oci_events_rule.Test_rule.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupRule(ctx *pulumi.Context, args *LookupRuleArgs, opts ...pulumi.InvokeOption) (*LookupRuleResult, error) {
	var rv LookupRuleResult
	err := ctx.Invoke("oci:events/getRule:getRule", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRule.
type LookupRuleArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this rule.
	RuleId string `pulumi:"ruleId"`
}

// A collection of values returned by getRule.
type LookupRuleResult struct {
	// A list of one or more Action objects.
	Actions GetRuleActions `pulumi:"actions"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter that specifies the event that will trigger actions associated with this rule. A few  important things to remember about filters:
	// * Fields not mentioned in the condition are ignored. You can create a valid filter that matches all events with two curly brackets: `{}`
	Condition string `pulumi:"condition"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A string that describes the details of the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.
	Description string `pulumi:"description"`
	// A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.  Example: `"This rule sends a notification upon completion of DbaaS backup."`
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this rule.
	Id string `pulumi:"id"`
	// Whether or not this rule is currently enabled.  Example: `true`
	IsEnabled bool `pulumi:"isEnabled"`
	// A message generated by the Events service about the current state of this rule.
	LifecycleMessage string `pulumi:"lifecycleMessage"`
	RuleId           string `pulumi:"ruleId"`
	// The current state of the rule.
	State string `pulumi:"state"`
	// The time this rule was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
	TimeCreated string `pulumi:"timeCreated"`
}
