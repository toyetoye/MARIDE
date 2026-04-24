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

