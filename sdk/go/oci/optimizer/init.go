// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package optimizer

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
	case "oci:optimizer/enrollmentStatus:EnrollmentStatus":
		r = &EnrollmentStatus{}
	case "oci:optimizer/profile:Profile":
		r = &Profile{}
	case "oci:optimizer/recommendation:Recommendation":
		r = &Recommendation{}
	case "oci:optimizer/resourceAction:ResourceAction":
		r = &ResourceAction{}
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
		"optimizer/enrollmentStatus",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"optimizer/profile",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"optimizer/recommendation",
		&module{version},
	)
	pulumi.RegisterResourceModule(
		"oci",
		"optimizer/resourceAction",
		&module{version},
	)
}
