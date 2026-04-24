# PROP to FORCAP Parity Matrix

This document maps legacy PROP functions to FORCAP modules and build requirements.

The first parity target is PROP Engineering / PMS because it is the core operational and future Class-facing module.

## Evidence Base

Initial mapping is based on:

- PROP Engineering worksheet history extract
- PROP Engineering screenshots and help material
- Existing FORCAP modules
- Technical Superintendent / former Chief Engineer domain validation

The PROP worksheet history shows that completed maintenance records are grouped by vessel, component, and criticality category. It includes fields such as vessel, official number, component code, component name, job code, job description, date completed, done-by rank/person, original due date, deferred-until date, job type, and Chief Engineer sign-off.

## Mapping Columns

| PROP Area | PROP Function | FORCAP Module | FORCAP Feature | Must Match PROP? | Improvement Opportunity | Priority | Notes |
|---|---|---|---|---:|---:|---:|---|

## PMS / Engineering Mapping

| PROP Area | PROP Function | FORCAP Module | FORCAP Feature | Must Match PROP? | Improvement Opportunity | Priority | Notes |
|---|---|---|---|---:|---:|---:|---|
| PROP Engineering | Vessel selection | FORCAP Core | Vessel Selector | Yes | Make vessel context persistent across all modules | P0 | Every module must operate under selected vessel context |
| PROP Engineering | Component hierarchy | Engineering / PMS | Engineering Component Explorer | Yes | Add search, filters, tree view, history tabs | P0 | Component code is central to PMS traceability |
| PROP Engineering | Critical Components section | Engineering / PMS | Component Criticality Classification | Yes | Dashboard by criticality | P0 | Must support Critical, Significant, and Standard grouping |
| PROP Engineering | Significant Components section | Engineering / PMS | Component Criticality Classification | Yes | Dashboard by criticality | P0 | Same report structure should be preserved |
| PROP Engineering | Completed Worksheets by Component | Engineering / PMS | Completed Worksheet History | Yes | Better filters, export, search, evidence view | P0 | Must preserve component, job, dates, rank/person, CE sign-off |
| PROP Engineering | Planned maintenance jobs | Engineering / PMS | PM Worksheet Templates | Yes | Better template control and revision history | P0 | Used to generate issued worksheets |
| PROP Engineering | Issued worksheets | Engineering / PMS | Issued Worksheet List | Yes | Better dashboard and overdue flags | P0 | Active PMS workload |
| PROP Engineering | Deferred worksheets | Engineering / PMS | Deferral Workflow | Yes | Add stricter audit and reason capture | P0 | Deferral is Class-sensitive |
| PROP Engineering | Chief Engineer sign-off | Engineering / PMS | CE Authorisation Queue | Yes | Better return/comment workflow | P0 | Completed jobs should not enter final history until authorised |
| PROP Engineering | Ad-hoc maintenance entries | Engineering / PMS | Ad-hoc Maintenance Report | Yes | Link to components, defects, files, actions | P1 | Must support historical ad-hoc work |
| PROP Engineering | Running-hour jobs | Engineering / PMS | Running Hours and Hourly Jobs | Yes | Link to EOM later | P1 | Hourly jobs require counter readings and next-due logic |
| PROP Engineering | Job code prefixes | Engineering / PMS | Job Type Classification | Yes | Use code families for filtering | P1 | Examples include K, T, I, S, R, C, TR and ad-hoc |
| PROP Engineering | Spare gear checks | Stores / Spares | Component-linked Spare Gear | Yes | Link PM jobs to spares and stock movements | P1 | Parts used should affect ROB after CE authorisation |
| PROP Engineering | PMS reports | Reports | PMS Report Centre | Yes | PDF, Excel, CSV, print preview | P0 | Reports are critical for audit and Class evidence |
| PROP Engineering | Completed history export | Reports | Completed Worksheet Export | Yes | Add filters and evidence pack export | P0 | Must reproduce familiar PROP report structure |
| PROP Finance | Requisitions | Finance / Requisitions | Requisition Workflow | Yes | Stronger status tracking | P1 | Later after PMS and spares foundation |
| PROP Refit | Maintenance Requirements | Refit | Refit MR Workflow | Yes | Better dashboards and attachments | P2 | Later module |
| PROP Forms | Risk assessments | Compliance | Risk Assessment Workflow | Yes | Link to jobs and permits later | P2 | Later module |
| PROP Forms | Daily / Weekly work plans | Operations | Work Planning | Partial | Already partly covered by Weekly Plan | P1 | Existing Weekly Plan module can be absorbed |

