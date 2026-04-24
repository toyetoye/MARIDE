# PMS / Class Evidence Plan

## Purpose

This document defines the evidence FORCAP should maintain to support future PMS/Class review.

FORCAP PMS should be designed from the beginning to preserve reliable maintenance evidence, access control, traceability, and authorised history.

## PMS Evidence Areas

FORCAP shall maintain evidence for:

- controlled user access
- vessel-specific component registry
- component criticality grouping
- planned maintenance templates
- maintenance interval logic
- running-hour maintenance logic
- condition-based maintenance support, later phase
- worksheet issuance
- worksheet completion
- deferral rules
- Chief Engineer authorisation
- completed maintenance history
- ad-hoc maintenance history
- report generation
- backup and restore process
- audit trail
- implementation and training records
- change/release control

## Evidence Records to Preserve

For Class/audit readiness, each major PMS feature should preserve:

- requirement ID
- design decision
- implementation reference
- test case
- test result
- screenshots or exported reports, where applicable
- user manual section
- approval/review record

## Critical PMS Evidence Requirements

### Completed Worksheet History

Completed history must preserve:

- vessel
- official number, where applicable
- component code
- component name
- criticality group
- job code
- job description
- completion date
- done-by rank
- done-by person
- original due date
- deferred-until date
- job type
- Chief Engineer sign-off

### Authorisation Evidence

The system must prove:

- who completed the worksheet
- when it was completed
- who authorised it
- when it was authorised
- whether it was returned before authorisation
- whether any parts/stock movements were triggered
- whether any record was later corrected

### Deferral Evidence

The system must prove:

- original due date
- deferred-until date
- deferral reason
- deferred by
- deferred date/time
- deferral approval, where applicable

### Access Evidence

The system must prove:

- user role
- vessel access
- module access
- action permission
- access changes over time

## Evidence Review Cadence

During development, PMS evidence should be reviewed at:

- end of each PMS feature
- end of each sprint
- before pilot vessel testing
- before Class pre-assessment
- before production release

