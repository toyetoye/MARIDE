# FORCAP PMS Requirements

## Purpose

The FORCAP Engineering/PMS module shall replace the core PROP Engineering planned maintenance workflows.

This module is the first serious FORCAP replacement target because it is operationally critical and likely to become the first Class-facing part of the product.

## PMS Product Goal

FORCAP PMS shall allow ship and shore users to:

- maintain a vessel-specific equipment/component registry
- define planned maintenance jobs
- issue worksheets
- complete maintenance work
- defer work under controlled conditions
- record running hours
- record ad-hoc maintenance
- require Chief Engineer authorisation
- preserve completed maintenance history
- produce familiar PMS reports
- provide audit and Class evidence

## Baseline PMS Record Requirements

A completed worksheet record shall preserve, at minimum:

- tenant/customer
- vessel
- vessel official number, where applicable
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
- completion comments
- running hours, where applicable
- attachments, where applicable
- audit trail

## Functional Requirements

### PMS-001 Component Registry

FORCAP shall maintain a vessel-specific component registry.

Each component shall support:

- component code
- component name
- vessel
- system/group
- assembly, where applicable
- parent component, where applicable
- criticality group
- active/inactive status
- class/survey relevance, where applicable
- linked PM templates
- linked spares
- linked files
- completed maintenance history

### PMS-002 Component Hierarchy

FORCAP shall support a hierarchy of:

- vessel
- system/group
- assembly
- component
- PM template
- issued worksheet
- completed worksheet
- spares
- files
- history

### PMS-003 Component Criticality

FORCAP shall support component criticality grouping.

Initial criticality groups:

- Critical
- Significant
- Standard

Criticality shall be available as a filter in:

- component explorer
- issued worksheets
- overdue worksheets
- completed worksheet history
- reports
- dashboards

### PMS-004 PM Worksheet Templates

FORCAP shall support planned maintenance worksheet templates.

A PM template shall support:

- component
- job code
- job title
- job description
- frequency type
- frequency value
- assigned rank
- job type
- safety notes
- required measurements
- required attachments
- related spares
- active/inactive status
- revision history

### PMS-005 Issued Worksheets

FORCAP shall issue worksheets from PM templates based on:

- calendar/date interval
- running hours
- condition-based requirement, later phase
- manual issue by authorised user

Issued worksheet fields shall include:

- worksheet number
- vessel
- component
- job code
- job description
- assigned rank
- original due date
- deferred-until date, where applicable
- status
- criticality
- type
- created/issued by
- created/issued date

### PMS-006 Deferral Workflow

FORCAP shall allow authorised users to defer worksheets according to configured rules.

Deferral shall require:

- permission
- reason
- new deferred-until date or running-hour counter
- audit event
- visibility in reports

### PMS-007 Completion Workflow

FORCAP shall allow assigned or authorised users to complete worksheet records.

Completion shall require:

- date completed
- completed by person
- completed by rank
- work comments
- measurements, where required
- running hours, where required
- parts used, where applicable
- attachments, where applicable

The system should discourage weak completion comments such as "done", "ok", or "satisfactory" where more detail is required.

### PMS-008 Chief Engineer Authorisation

FORCAP shall require Chief Engineer or authorised role review before a completed worksheet enters final maintenance history.

### PMS-009 Return Workflow

FORCAP shall allow the Chief Engineer or authorised role to return a completed worksheet for correction.

Return shall require:

- reason
- returned by
- returned date
- audit event

### PMS-010 Completed Worksheet History

FORCAP shall preserve completed worksheet history by:

- vessel
- component
- job
- date range
- rank/person
- criticality
- job type
- due/completed/deferred status

### PMS-011 Ad-hoc Maintenance

FORCAP shall allow users to enter ad-hoc maintenance reports linked to:

- vessel
- component, where applicable
- responsible rank/person
- date completed
- description
- attachments
- related defect/action, later phase

### PMS-012 Running Hours

FORCAP shall record running hours and support running-hour-based maintenance triggers.

Running-hour records shall support:

- vessel
- equipment/component
- counter name
- reading
- reading date/time
- entered by
- source module, if linked from EOM later
- audit event

### PMS-013 PMS Reports

FORCAP shall generate PMS reports comparable to PROP reports.

Initial PMS reports:

- Completed Worksheets by Component
- Completed Worksheets by Job
- Issued Worksheets
- Deferred Worksheets
- Overdue Worksheets
- Worksheets Awaiting Authorisation
- Running Hours Sheet
- Component History
- Ad-hoc Maintenance History
- Critical Component Maintenance History
- Significant Component Maintenance History
- Maintenance Forecast

## Non-functional Requirements

- All critical PMS actions shall be audited.
- Access shall be controlled by user, role, vessel, module, and action.
- PMS history shall be immutable after authorisation except through a controlled correction/revision process.
- Reports shall be exportable.
- The system shall support future Class evidence requirements.
- The system shall support shipboard low-connectivity workflows later through draft/autosave and sync status.

