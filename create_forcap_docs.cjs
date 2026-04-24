const fs = require("fs");
const path = require("path");

const folders = [
  "docs/00-governance",
  "docs/01-product",
  "docs/02-prop-replacement",
  "docs/03-requirements",
  "docs/04-access-control",
  "docs/05-architecture",
  "docs/06-pms-class-evidence",
  "docs/07-security-iso27001",
  "docs/08-quality-iso9001",
  "docs/09-testing",
  "docs/10-user-docs",
  "docs/11-operations",
  "docs/12-audit-evidence",
  "docs/templates"
];

for (const folder of folders) {
  fs.mkdirSync(path.join(process.cwd(), folder), { recursive: true });
}

function writeFile(filePath, content) {
  const fullPath = path.join(process.cwd(), filePath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, content.trimStart() + "\n", "utf8");
  console.log("created/updated " + filePath);
}

writeFile("docs/README.md", `
# FORCAP Documentation Framework

This folder contains the controlled documentation framework for FORCAP.

FORCAP is being developed as a maritime enterprise vessel fleet management suite intended to replace legacy PROP-style ship/shore workflows and support future audit, compliance, Class review, ISO readiness, customer onboarding, and commercial licensing.

Documentation must be maintained as the product is built.

## Documentation Rule

A FORCAP feature is not complete unless the relevant documentation is updated:

- requirement
- access-control rule
- audit event, where applicable
- test case
- user/admin guidance, where applicable
- release note

## Structure

- 00-governance - decisions, change control, release governance
- 01-product - product charter, module map, MVP scope
- 02-prop-replacement - PROP-to-FORCAP mapping
- 03-requirements - functional and non-functional requirements
- 04-access-control - roles, permissions, user/vessel access
- 05-architecture - system, database, API, deployment architecture
- 06-pms-class-evidence - PMS/Class readiness evidence
- 07-security-iso27001 - security and ISMS documentation
- 08-quality-iso9001 - quality management documentation
- 09-testing - test strategy, test cases, acceptance evidence
- 10-user-docs - user/admin guides
- 11-operations - backup, restore, monitoring, support
- 12-audit-evidence - evidence register and audit trail mapping
- templates - reusable documentation templates
`);

writeFile("docs/01-product/product-charter.md", `
# FORCAP Product Charter

## Product Name

FORCAP

## Product Category

Maritime enterprise vessel fleet management suite.

## Product Purpose

FORCAP is a web-based, access-controlled maritime operations platform designed to replace legacy PROP-style ship/shore systems and provide a modern suite for vessel fleet management.

FORCAP will support:

- vessel technical management
- planned maintenance
- spares and stores
- requisitions and finance workflows
- engineering logbook
- fuel and voyage reporting
- inspection readiness
- SIRE findings
- HSSE and investigations
- refit and claims
- documents and knowledge
- AI-assisted operational support
- fleet reporting

## Replacement Target

The initial replacement target is the current PROP structure, especially:

- PROP Engineering
- PROP Finance
- PROP Forms
- Refit and claims
- Office Desktop vessel selection
- ship/shore access control
- PMS reports
- completed worksheet history
- spare gear and stores
- requisitions
- daily and weekly work plans
- risk assessments

## Product Principle

FORCAP should preserve the mental model of PROP where useful:

- select vessel
- choose module
- work inside vessel context
- respect access rights
- produce familiar reports
- preserve ship/shore workflow

FORCAP should improve:

- navigation
- search
- audit trail
- reports
- dashboards
- role-based access
- data consistency
- security
- user experience
- multi-vessel reporting
- future AI support

## First Serious Product Target

FORCAP Core plus Engineering/PMS.

## First Commercial MVP

- Core
- PMS / Engineering
- Completed worksheet history
- Issued worksheets
- Deferrals
- Chief Engineer authorisation
- Reports
- Basic spares/stores link
`);

writeFile("docs/01-product/module-map.md", `
# FORCAP Module Map

## FORCAP Core

- users
- roles
- permissions
- vessels
- user-vessel access
- module access
- audit trail
- files
- notifications
- reports
- tenant/customer licensing later

## Engineering / PMS

- component registry
- equipment hierarchy
- PM templates
- issued worksheets
- completed worksheets
- deferred worksheets
- ad-hoc maintenance
- running hours
- operating parameters
- Chief Engineer authorisation
- maintenance history
- PMS reports

## Stores / Spares

- spare gear
- stores
- ROB
- minimum stock
- expiry dates
- stock checks
- parts used
- requisition trigger

## Finance / Requisitions

- requisitions
- outport purchases
- vendors
- quotes
- budgets
- goods received
- head office / SAP workflow

## Operations

- EOM logbook
- noon reports
- fuel
- voyages
- port operations
- daily work plans
- weekly work plans

## Compliance

- SIRE
- HSSE
- risk assessments
- investigations
- refit
- MLA
- claims
- evidence packs

## Knowledge / Oracle

- manuals
- documents
- search
- controlled AI assistant
- report drafting
`);

writeFile("docs/01-product/mvp-scope.md", `
# FORCAP MVP Scope

## MVP Objective

Build a working FORCAP Core and Engineering/PMS module that can demonstrate replacement of the most important PROP Engineering workflows.

## MVP Modules

- FORCAP Core
- FORCAP Engineering / PMS
- FORCAP Reports
- Basic Spares Link
- Admin / Access Control

## MVP Screens

- Login
- FORCAP Desktop
- Vessel Selector
- Vessel Workspace
- Engineering Dashboard
- Component Explorer
- PM Worksheet Templates
- Issued Worksheets
- Deferred Worksheets
- Complete Worksheet
- Chief Engineer Authorisation
- Completed Worksheet History
- Ad-hoc Maintenance
- Running Hours
- PMS Reports
- User Management
- Role / Access Management
- Audit Log

## MVP Reports

- Completed Worksheets by Component
- Completed Worksheets by Job
- Overdue Worksheets
- Issued Worksheets
- Deferred Worksheets
- Worksheets Awaiting Authorisation
- Running Hours Sheet
- Maintenance Forecast
- Component History
- Ad-hoc Maintenance History
- Critical Component Maintenance History
`);

writeFile("docs/02-prop-replacement/prop-to-forcap-parity-matrix.md", `
# PROP to FORCAP Parity Matrix

This document maps legacy PROP functions to FORCAP modules and features.

## Mapping Columns

| PROP Area | PROP Function | FORCAP Module | FORCAP Feature | Must Match PROP? | Improvement Opportunity | Priority | Notes |
|---|---|---|---|---:|---:|---:|---|

## Initial PMS Mapping

| PROP Area | PROP Function | FORCAP Module | FORCAP Feature | Must Match PROP? | Improvement Opportunity | Priority | Notes |
|---|---|---|---|---:|---:|---:|---|
| PROP Engineering | Completed Worksheets by Component | Engineering / PMS | Completed Worksheet History | Yes | Better filters, export, search | P0 | Must preserve vessel, component, job, dates, rank/person, CE sign-off |
| PROP Engineering | Issued Worksheets | Engineering / PMS | Issued Worksheet List | Yes | Better dashboard and overdue flags | P0 | Active PMS workload |
| PROP Engineering | Deferred Worksheets | Engineering / PMS | Deferral Workflow | Yes | Add stricter audit and reason capture | P0 | Defer rules are Class-sensitive |
| PROP Engineering | Chief Engineer Authorisation | Engineering / PMS | CE Authorisation Queue | Yes | Better return/comment workflow | P0 | Completed jobs should not enter final history until authorised |
| PROP Engineering | Ad-hoc Maintenance | Engineering / PMS | Ad-hoc Maintenance Report | Yes | Link to components, defects, files | P1 | Must support historical ad-hoc work |
| PROP Engineering | Running Hours | Engineering / PMS | Running Hours | Yes | Link to EOM later | P1 | Required for hourly jobs |
| PROP Engineering | Component Explorer | Engineering / PMS | Engineering Explorer | Yes | Modern searchable tree | P0 | Component-driven PMS model |
| PROP Engineering | Spare Gear | Stores / Spares | Component-linked Spares | Yes | Link to PMS and requisitions | P1 | Parts used should affect ROB after authorisation |
| PROP Finance | Requisitions | Finance / Requisitions | Requisition Workflow | Yes | Stronger status tracking | P1 | Later module |
| PROP Refit | Maintenance Requirements | Refit | Refit MR Workflow | Yes | Better dashboards and attachments | P2 | Later module |
`);

writeFile("docs/03-requirements/pms-requirements.md", `
# FORCAP PMS Requirements

## Purpose

The FORCAP Engineering/PMS module shall replace the core PROP Engineering planned maintenance workflows.

## Baseline PMS Record Requirements

A completed worksheet record shall preserve, at minimum:

- tenant/customer
- vessel
- official number, where applicable
- component code
- component name
- component criticality group
- job code
- job description
- job type
- original due date
- deferred-until date, where applicable
- date completed
- completed by rank
- completed by person
- Chief Engineer authorisation/sign-off
- comments
- attachments, where applicable
- audit trail

## Functional Requirements

### PMS-001 Component Registry

FORCAP shall maintain a vessel-specific component registry.

### PMS-002 Component Hierarchy

FORCAP shall support a hierarchy of vessel, system/group, assembly, component, PM template, issued worksheet, completed worksheet, spares, files, and history.

### PMS-003 PM Worksheet Templates

FORCAP shall support planned maintenance worksheet templates.

### PMS-004 Issued Worksheets

FORCAP shall issue worksheets from PM templates based on date, running hours, or condition-based logic.

### PMS-005 Deferral Workflow

FORCAP shall allow authorised users to defer worksheets according to configured rules.

### PMS-006 Completion Workflow

FORCAP shall allow assigned users to complete worksheet records with meaningful work comments.

### PMS-007 Chief Engineer Authorisation

FORCAP shall require Chief Engineer or authorised role review before a completed worksheet enters final maintenance history.

### PMS-008 Return Workflow

FORCAP shall allow the Chief Engineer to return a completed worksheet for correction with a mandatory reason.

### PMS-009 Completed Worksheet History

FORCAP shall preserve completed worksheet history by component and job.

### PMS-010 Ad-hoc Maintenance

FORCAP shall allow users to enter ad-hoc maintenance reports linked to a vessel and, where applicable, a component.

### PMS-011 Running Hours

FORCAP shall record running hours and support running-hour-based maintenance triggers.

### PMS-012 PMS Reports

FORCAP shall generate PMS reports comparable to PROP reports, including completed worksheets by component.

## Non-functional Requirements

- All critical PMS actions shall be audited.
- Access shall be controlled by user, role, vessel, module, and action.
- PMS history shall be immutable after authorisation except through controlled correction/revision process.
- Reports shall be exportable.
- The system shall support future Class evidence requirements.
`);

writeFile("docs/04-access-control/roles-and-permissions.md", `
# FORCAP Roles and Permissions

## Access Model

FORCAP permissions are based on:

- user identity
- role
- vessel assignment
- module access
- action-level permission
- ship/shore context

## Initial Roles

- System Admin
- Company Admin
- Fleet Manager
- Technical Manager
- Marine Superintendent
- Technical Superintendent
- Master
- Chief Engineer
- Chief Officer
- Second Engineer
- Third Engineer
- Fourth Engineer
- Electrical Officer
- Finance User
- Procurement User
- Stores User
- Auditor / Surveyor
- Supplier / Agent
- Read-only User

## Action Permissions

- view
- create
- update
- delete
- issue
- assign
- defer
- complete
- return
- authorise
- close
- print
- export
- approve
- send_to_office
- receive_goods
- configure

## PMS-Specific Permission Rules

| Action | Typical Roles | Notes |
|---|---|---|
| View issued worksheets | Engineering officers, CE, superintendent | Vessel access required |
| Complete worksheet | Assigned rank/officer, CE | Vessel access required |
| Defer worksheet | CE, superintendent, authorised roles | Defer reason required |
| Return worksheet | CE, superintendent | Return reason required |
| Authorise worksheet | CE, authorised superintendent | Required before final history |
| Configure PM templates | Superintendent, admin | Controlled access |
| Export PMS reports | CE, superintendent, auditor | Audit event required |
`);

writeFile("docs/04-access-control/access-matrix.md", `
# FORCAP Access Matrix

| Module | Feature | Action | System Admin | Superintendent | Master | Chief Engineer | 2nd Engineer | 3rd Engineer | Auditor |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| Core | Users | Manage | Yes | No | No | No | No | No | No |
| Core | Vessels | Manage | Yes | Yes | No | No | No | No | View |
| PMS | Component Registry | View | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| PMS | Component Registry | Configure | Yes | Yes | No | Limited | No | No | No |
| PMS | Issued Worksheets | View | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| PMS | Issued Worksheets | Complete | Yes | Limited | No | Yes | Yes | Yes | No |
| PMS | Worksheets | Defer | Yes | Yes | No | Yes | No | No | No |
| PMS | Worksheets | Return | Yes | Yes | No | Yes | No | No | No |
| PMS | Worksheets | Authorise | Yes | Yes | No | Yes | No | No | No |
| PMS | Reports | Export | Yes | Yes | Yes | Yes | Limited | Limited | Yes |
`);

writeFile("docs/05-architecture/system-architecture.md", `
# FORCAP System Architecture

## Target Architecture

FORCAP should become one platform with one shell, one access-control model, one vessel registry, one audit trail, and module-based functionality.

## Proposed Structure

forcap-platform/
- apps/
  - web/
  - api/
- modules/
  - core/
  - pms/
  - spares/
  - finance/
  - operations/
  - compliance/
  - knowledge/
- packages/
  - ui/
  - auth/
  - db/
  - audit/
  - config/
- docs/

## Current Transition Plan

MARIDE is the current FORCAP shell candidate. Existing apps should be treated as module prototypes and gradually migrated into the unified FORCAP shell.

## Core Platform Services

- authentication
- roles and permissions
- vessel registry
- audit logging
- file storage
- notifications
- reporting
- tenant/customer management later
`);

writeFile("docs/05-architecture/data-model-v0.1.md", `
# FORCAP Data Model v0.1

## Core Schema

- core.tenants
- core.users
- core.roles
- core.permissions
- core.user_roles
- core.vessels
- core.user_vessels
- core.modules
- core.module_permissions
- core.audit_events
- core.files
- core.comments
- core.actions
- core.notifications

## PMS Schema

- pms.component_groups
- pms.assemblies
- pms.components
- pms.component_criticalities
- pms.pm_templates
- pms.pm_template_revisions
- pms.issued_worksheets
- pms.completed_worksheets
- pms.deferred_worksheets
- pms.cbm_assessments
- pms.running_hours
- pms.operating_parameter_results
- pms.parts_used
- pms.worksheet_files
- pms.ad_hoc_reports
- pms.maintenance_history_archive

## Spares Schema

- spares.parts
- spares.part_locations
- spares.part_manufacturers
- spares.stock_balances
- spares.stock_movements
- spares.medical_locker_items
- spares.holding_bay
- spares.stock_checks
- spares.expiry_warnings
- spares.part_component_links

## Finance Schema

- finance.budget_codes
- finance.budgets
- finance.vendors
- finance.currencies
- finance.requisitions
- finance.requisition_items
- finance.quotes
- finance.goods_receipts
- finance.sap_transmissions
- finance.status_logs
`);

writeFile("docs/06-pms-class-evidence/pms-class-evidence-plan.md", `
# PMS / Class Evidence Plan

## Purpose

This document defines the evidence FORCAP should maintain to support future PMS/Class review.

## PMS Evidence Areas

- controlled user access
- vessel-specific component registry
- planned maintenance templates
- maintenance interval logic
- running-hour maintenance logic
- condition-based maintenance support
- worksheet issuance
- worksheet completion
- deferral rules
- Chief Engineer authorisation
- maintenance history preservation
- report generation
- backup and restore process
- audit trail
- implementation and training records
- change/release control

## Evidence Records to Preserve

- requirement ID
- design decision
- implementation reference
- test case
- test result
- screenshots or exported reports, where applicable
- user manual section
- approval/review record
`);

writeFile("docs/06-pms-class-evidence/pms-chief-engineer-authorisation.md", `
# Chief Engineer Authorisation

## Purpose

Completed PMS worksheets shall not enter final maintenance history until reviewed and authorised by the Chief Engineer or another authorised role.

## Workflow

1. Officer completes worksheet.
2. Worksheet enters Awaiting Authorisation.
3. Chief Engineer reviews work comments, dates, parts used, measurements, and attachments.
4. Chief Engineer either authorises or returns the worksheet.
5. If returned, a reason is mandatory.
6. If authorised, worksheet enters completed history.
7. Any parts used may update ROB only after authorisation.

## Required Audit Events

- worksheet_completed
- worksheet_submitted_for_authorisation
- worksheet_returned
- worksheet_authorised
- worksheet_history_created
- stock_adjusted_from_authorised_worksheet, where applicable

## Access Rules

- Completion allowed by assigned/authorised engineering users.
- Authorisation allowed by Chief Engineer or authorised superintendent/admin role.
- Return reason required.
- Authorised history must be immutable except through controlled correction/revision.
`);

writeFile("docs/07-security-iso27001/security-overview.md", `
# FORCAP Security Overview

## Security Objectives

FORCAP shall protect confidentiality, integrity, and availability of customer and vessel data.

## Initial Controls

- unique user accounts
- password hashing
- role-based access control
- vessel-level access control
- module-level access control
- action-level permissions
- session expiry
- audit logging
- secure file upload validation
- environment validation
- restricted CORS
- rate limiting
- backup and restore testing
- separation of development, staging, and production environments

## Pre-launch Security Requirements

- remove all default production passwords
- remove fallback JWT/session secrets
- centralise authentication
- remove query-string authentication tokens
- add production environment validation
- add monitoring and error logging
`);

writeFile("docs/08-quality-iso9001/quality-management-plan.md", `
# FORCAP Quality Management Plan

## Purpose

This document defines the initial quality management approach for FORCAP development.

## Quality Principles

- requirements are documented
- changes are controlled
- releases are versioned
- tests are recorded
- defects are tracked
- user feedback is reviewed
- documentation is maintained
- audit evidence is preserved

## Definition of Done

A feature is complete only when:

1. Requirement is documented.
2. Access-control rule is documented.
3. Audit event is documented, where applicable.
4. Test case is documented.
5. User/admin documentation is updated, where applicable.
6. Release notes are updated.
`);

writeFile("docs/09-testing/test-strategy.md", `
# FORCAP Test Strategy

## Test Types

- unit tests
- API tests
- integration tests
- role/access tests
- vessel access tests
- workflow tests
- report tests
- audit log tests
- backup/restore tests
- user acceptance tests

## PMS Acceptance Focus

- issued worksheets display correctly
- overdue worksheets are identified
- deferral requires permission and reason
- completed worksheet requires meaningful completion data
- CE authorisation is required before final history
- returned worksheet requires a reason
- component history is preserved
- reports match required fields
- vessel access prevents cross-vessel data access
`);

writeFile("docs/10-user-docs/chief-engineer-guide.md", `
# Chief Engineer Guide

## Purpose

This guide will explain Chief Engineer workflows in FORCAP.

## Initial Workflows

- review engineering dashboard
- view issued worksheets
- complete worksheet
- defer worksheet
- review completed worksheets
- return worksheet for correction
- authorise worksheet
- view completed worksheet history
- enter ad-hoc maintenance
- review running hours
- export PMS reports

## Authorisation Principle

A completed worksheet is not final until authorised by the Chief Engineer or authorised role.
`);

writeFile("docs/11-operations/backup-restore-procedure.md", `
# Backup and Restore Procedure

## Purpose

FORCAP must support reliable backup and restoration of operational and compliance data.

## Minimum Requirements

- scheduled database backups
- object/file storage backup process
- restore testing
- restore test records
- backup retention policy
- access control for backups
- incident process for failed backups

## Evidence

Restore tests shall be logged in the audit/evidence register.
`);

writeFile("docs/12-audit-evidence/evidence-register.md", `
# FORCAP Evidence Register

This register tracks evidence produced during product development and testing.

| Evidence ID | Area | Description | Source / Location | Date | Owner | Status |
|---|---|---|---|---|---|---|
| EVD-0001 | Product | Documentation framework created | docs/ | TBD | FORCAP | Draft |
| EVD-0002 | PMS | PROP completed worksheet report reviewed | Uploaded PROP worksheet history | TBD | FORCAP | Source reviewed |
`);

writeFile("docs/templates/feature-spec-template.md", `
# Feature Specification Template

## Feature Name

## PROP Equivalent

## Purpose

## User Roles

## Workflow

## Required Fields

## Statuses

## Permissions

## Audit Events

## Reports

## Validation Rules

## Acceptance Criteria

## Test Cases

## User Documentation Impact

## Compliance / Class Impact

## Notes
`);

writeFile("docs/templates/decision-record-template.md", `
# Architecture / Product Decision Record

## Decision ID

## Date

## Decision

## Context

## Options Considered

## Chosen Approach

## Reason

## Impact

## Follow-up Actions

## Owner
`);

console.log("");
console.log("FORCAP docs scaffold created successfully.");
console.log("Next commands:");
console.log("git status");
console.log("git add docs create_forcap_docs.cjs");
console.log("git commit -m \"Add FORCAP documentation and compliance framework\"");
console.log("git push -u origin docs/forcap-compliance-framework");