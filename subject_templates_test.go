package main

import (
	"bytes"
	"strings"
	"testing"
	"text/template"

	"github.com/compliance-framework/agent/runner/proto"
)

func TestBuildSubjectTemplatesIncludesVpcResourceFamilies(t *testing.T) {
	templates := buildSubjectTemplates()
	if len(templates) != 5 {
		t.Fatalf("expected five subject templates, got %d", len(templates))
	}

	names := map[string]bool{}
	for _, template := range templates {
		names[template.Name] = true
	}

	for _, expected := range []string{
		"aws-vpc",
		"aws-vpc-subnet",
		"aws-vpc-security-group",
		"aws-vpc-network-acl",
		"aws-vpc-route-table",
	} {
		if !names[expected] {
			t.Fatalf("missing subject template %s", expected)
		}
	}
}

func TestSubjectTemplatesHaveSelectorsAndSchemasForIdentity(t *testing.T) {
	for _, subjectTemplate := range buildSubjectTemplates() {
		if subjectTemplate.Type != proto.SubjectType_SUBJECT_TYPE_COMPONENT {
			t.Fatalf("template %s must use component subject type", subjectTemplate.Name)
		}
		if len(subjectTemplate.SelectorLabels) == 0 {
			t.Fatalf("template %s missing selector labels", subjectTemplate.Name)
		}
		if !containsSchemaKey(subjectTemplate.LabelSchema, "type") {
			t.Fatalf("template %s must declare type selector in label schema", subjectTemplate.Name)
		}

		for _, selector := range subjectTemplate.SelectorLabels {
			if strings.Contains(selector.Key, "-") {
				t.Fatalf("template %s selector key %s must use underscore notation", subjectTemplate.Name, selector.Key)
			}
		}

		for _, identityKey := range subjectTemplate.IdentityLabelKeys {
			if strings.Contains(identityKey, "-") {
				t.Fatalf("template %s identity key %s must use underscore notation", subjectTemplate.Name, identityKey)
			}
			if !containsSchemaKey(subjectTemplate.LabelSchema, identityKey) {
				t.Fatalf("template %s identity key %s missing from label schema", subjectTemplate.Name, identityKey)
			}
		}

		for _, field := range subjectTemplate.LabelSchema {
			if strings.Contains(field.Key, "-") {
				t.Fatalf("template %s schema key %s must use underscore notation", subjectTemplate.Name, field.Key)
			}
		}
	}
}

func TestSubjectTemplateTitleAndDescriptionRenderWithUnderscoreLabels(t *testing.T) {
	labels := map[string]string{
		"provider":       "aws",
		"type":           "route-table",
		"vpc_id":         "vpc-123",
		"cidr":           "10.0.0.0/16",
		"region":         "eu-west-2",
		"subnet_id":      "subnet-123",
		"az":             "eu-west-2a",
		"group_id":       "sg-123",
		"acl_id":         "acl-123",
		"route_table_id": "rtb-123",
	}

	for _, subjectTemplate := range buildSubjectTemplates() {
		for fieldName, templateText := range map[string]string{
			"title":       subjectTemplate.TitleTemplate,
			"description": subjectTemplate.DescriptionTemplate,
			"purpose":     subjectTemplate.PurposeTemplate,
		} {
			if rendered := renderSubjectTemplate(t, subjectTemplate.Name, fieldName, templateText, labels); rendered == "" {
				t.Fatalf("template %s rendered empty %s", subjectTemplate.Name, fieldName)
			}
		}
	}
}

func containsSchemaKey(schema []*proto.SubjectLabelSchema, target string) bool {
	for _, field := range schema {
		if field.Key == target {
			return true
		}
	}
	return false
}

func renderSubjectTemplate(t *testing.T, templateName, fieldName, templateText string, labels map[string]string) string {
	t.Helper()

	parsed, err := template.New(templateName + "-" + fieldName).Option("missingkey=zero").Parse(templateText)
	if err != nil {
		t.Fatalf("template %s has invalid %s template: %v", templateName, fieldName, err)
	}

	var buf bytes.Buffer
	if err := parsed.Execute(&buf, labels); err != nil {
		t.Fatalf("template %s failed to render %s template: %v", templateName, fieldName, err)
	}
	return buf.String()
}
