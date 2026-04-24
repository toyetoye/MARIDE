# Feature Specification: PMS Issued Worksheets

## Feature Name

Issued Worksheets

## PROP Equivalent

PROP Engineering issued worksheets.

## Purpose

The Issued Worksheets feature shows active maintenance jobs issued for a selected vessel.

## User Roles

- Chief Engineer
- Technical Superintendent
- Engineering Officers
- Auditor / Surveyor, read-only

## Workflow

1. User selects vessel.
2. User opens Engineering / PMS.
3. User opens Issued Worksheets.
4. User filters by status, due date, rank, component, job type, or criticality.
5. User opens a worksheet.
6. User may start, complete, defer, print, or view history depending on permission.

## Required Fields

- worksheet number
- vessel
- component code
- component name
- criticality
- job code
- job description
- assigned rank
- original due date
- deferred-until date
- job type
- status
- issued date
- issued by

## Statuses

- Issued
- In Progress
- Deferred
- Completed Awaiting Authorisation
- Returned for Correction
- Authorised
- Cancelled

## Permissions

| Action | Permission |
|---|---|
| View issued worksheets | pms.worksheets.view |
| Complete worksheet | pms.worksheets.complete |
| Defer worksheet | pms.worksheets.defer |
| Return worksheet | pms.worksheets.return |
| Authorise worksheet | pms.worksheets.authorise |
| Export / print worksheet | pms.worksheets.export |

## Audit Events

- pms_worksheet_issued
- pms_worksheet_viewed
- pms_worksheet_started
- pms_worksheet_deferred
- pms_worksheet_completed
- pms_worksheet_returned
- pms_worksheet_authorised
- pms_worksheet_cancelled

## Acceptance Criteria

- Only users with vessel access can view worksheets.
- Overdue worksheets are clearly flagged.
- Deferred worksheets show the deferred-until date.
- Completed worksheets do not enter final history until authorised.
- Every status change is audited.

