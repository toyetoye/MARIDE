# Feature Specification: PMS Deferral Workflow

## Feature Name

PMS Deferral Workflow

## PROP Equivalent

PROP Engineering deferred worksheets.

## Purpose

The Deferral Workflow allows authorised users to defer maintenance work while preserving reason, due-date impact, and audit evidence.

## User Roles

- Chief Engineer
- Technical Superintendent
- Marine Superintendent
- System Admin

## Workflow

1. User opens issued worksheet.
2. User selects Defer.
3. System checks permission.
4. User enters deferral reason.
5. User enters new deferred-until date or running-hour value.
6. System validates against configured rules.
7. Worksheet status changes to Deferred.
8. Audit event is recorded.

## Required Fields

- worksheet
- current due date
- new deferred-until date
- current running hours, where applicable
- deferred-until running hours, where applicable
- deferral reason
- deferred by
- deferred date/time
- approval status, where applicable

## Permissions

| Action | Permission |
|---|---|
| Defer worksheet | pms.worksheets.defer |
| Approve extended deferral | pms.worksheets.defer_approve |
| View deferral history | pms.worksheets.defer_history |

## Audit Events

- pms_worksheet_deferral_requested
- pms_worksheet_deferred
- pms_worksheet_deferral_rejected
- pms_worksheet_deferral_overridden

## Acceptance Criteria

- Deferral requires reason.
- Deferral requires authorised permission.
- Original due date is preserved.
- Deferred-until date is preserved.
- Deferral appears in reports.
- Deferral history is visible.

