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

