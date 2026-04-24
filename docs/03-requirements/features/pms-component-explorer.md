# Feature Specification: PMS Component Explorer

## Feature Name

PMS Component Explorer

## PROP Equivalent

PROP Engineering component explorer / component-based PMS history.

## Purpose

The Component Explorer is the main navigation and evidence view for PMS data. It allows users to browse vessel equipment/components and see templates, issued worksheets, completed history, spares, files, and audit evidence for each component.

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
3. User opens Component Explorer.
4. User searches or filters component list.
5. User selects a component.
6. FORCAP displays component details, active PM jobs, issued worksheets, completed history, spares, files, and audit events.

## Required Fields

- component code
- component name
- vessel
- system/group
- assembly, where applicable
- criticality group
- active/inactive status
- linked PM templates
- linked history
- linked spares
- linked documents

## Permissions

| Action | Permission |
|---|---|
| View components | pms.components.view |
| Create component | pms.components.create |
| Edit component | pms.components.update |
| Deactivate component | pms.components.deactivate |
| Export component history | pms.components.export |

## Audit Events

- pms_component_created
- pms_component_updated
- pms_component_deactivated
- pms_component_history_exported

## Acceptance Criteria

- User can only view components for vessels they are assigned to.
- Components can be filtered by criticality.
- Component details show active PM templates.
- Component details show issued worksheets.
- Component details show completed history.
- Component details show linked spares and files when available.

