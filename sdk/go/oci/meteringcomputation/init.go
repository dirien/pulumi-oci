// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package meteringcomputation

import (
	"fmt"

	"github.com/blang/semver"
	"github.com/pulumi/pulumi-oci/sdk/go/oci"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type module struct {
	version semver.Version
}

func (m *module) Version() semver.Version {
	return m.version
}

func (m *module) Construct(ctx *pulumi.Context, name, typ, urn string) (r pulumi.Resource, err error) {
	switch typ {
	case "oci:meteringcomputation/customTable:CustomTable":
		r = &CustomTable{}
	case "oci:meteringcomputation/query:Query":
		r = &Query{}
	case "oci:meteringcomputation/usage:Usage":
		r = &Usage{}
	default:
		return nil, fmt.Errorf("unknown resource type: %s", typ)
	}

	err = ctx.RegisterResource(typ, name, nil, r, pulumi.URN_(urn))
	return
}

func init() {
	version, err := oci.PkgVersion()
	if err != nil {
		fmt.Printf("failed to determine package version. defaulting to v1: %v\n", err)
	}
	pulumi.RegisterResourceModule(
		"oci",
		"meteringcomputation/customTable",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"meteringcomputation/query",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"meteringcomputation/usage",
		&module{version},
	)
}
