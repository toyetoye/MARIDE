# Feature Specification: PMS Chief Engineer Authorisation

## Feature Name

Chief Engineer Authorisation

## PROP Equivalent

PROP Engineering Chief Engineer sign-off / authorisation of completed worksheets.

## Purpose

Completed PMS worksheets shall not enter final maintenance history until reviewed and authorised by the Chief Engineer or another authorised role.

## User Roles

- Chief Engineer
- Technical Superintendent, where authorised
- System Admin, exceptional use only

## Workflow

1. Officer completes worksheet.
2. Worksheet status becomes Completed Awaiting Authorisation.
3. Chief Engineer opens authorisation queue.
4. Chief Engineer reviews work comments, dates, parts used, measurements, running hours, and attachments.
5. Chief Engineer authorises or returns the worksheet.
6. If returned, a reason is mandatory.
7. If authorised, worksheet enters completed history.
8. Parts used may update ROB only after authorisation.

## Required Fields

- worksheet
- completed by
- completed date
- work comments
- reviewed by
- review date
- authorisation decision
- return reason, where applicable
- Chief Engineer sign-off
- audit event

## Permissions

| Action | Permission |
|---|---|
| View authorisation queue | pms.authorisation.view |
| Authorise worksheet | pms.authorisation.authorise |
| Return worksheet | pms.authorisation.return |

## Audit Events

- pms_worksheet_completed
- pms_worksheet_submitted_for_authorisation
- pms_worksheet_returned
- pms_worksheet_authorised
- pms_history_record_created
- spares_stock_adjusted_from_authorised_worksheet, where applicable

## Acceptance Criteria

- Completed worksheet does not enter final history without authorisation.
- Authorisation requires authorised role.
- Returned worksheet requires reason.
- Authorised record is locked from normal editing.
- Audit log records every authorisation decision.

