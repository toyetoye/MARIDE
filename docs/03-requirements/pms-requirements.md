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

