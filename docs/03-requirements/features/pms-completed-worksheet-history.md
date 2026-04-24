# Feature Specification: PMS Completed Worksheet History

## Feature Name

Completed Worksheet History

## PROP Equivalent

PROP Engineering Completed Worksheets by Component report.

## Purpose

Completed Worksheet History preserves authorised PMS records for vessel, component, audit, Class, and operational review.

## User Roles

- Chief Engineer
- Technical Superintendent
- Marine Superintendent
- Engineering Officers
- Auditor / Surveyor
- System Admin

## Workflow

1. User selects vessel.
2. User opens Engineering / PMS.
3. User opens Completed Worksheet History.
4. User selects date range.
5. User filters by component, criticality, job code, rank/person, or job type.
6. User views or exports report.

## Required Fields

- vessel
- official number
- component code
- component name
- criticality group
- job code
- job description
- date completed
- done by rank
- done by person
- original due date
- deferred-until date
- job type
- Chief Engineer sign-off
- completion comments
- running hours, where applicable
- attachments, where applicable

## Report Grouping

The report shall support grouping by:

- Critical Components
- Significant Components
- Standard Components
- component code and name
- job code
- date range

## Permissions

| Action | Permission |
|---|---|
| View completed history | pms.history.view |
| Export completed history | pms.history.export |
| Correct authorised record | pms.history.correct |

## Audit Events

- pms_history_viewed
- pms_history_exported
- pms_history_record_created
- pms_history_record_corrected

## Acceptance Criteria

- Report can be filtered by date range.
- Report can be grouped by component.
- Report shows criticality grouping.
- Report includes due, deferred, and completed dates.
- Report includes done-by rank/person.
- Report includes Chief Engineer sign-off.
- Authorised records cannot be casually edited.

