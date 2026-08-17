# Templates

This directory contains infrastructure deployment templates for the Guest Permissions solution package.

## Contents

- `azuredeploy/guest-permissions-solution.json` — ARM template used by the Deploy-to-Azure button
- `azuredeploy/guest-permissions-solution.parameters.json` — sample parameter values
- `azuredeploy/guest-permissions-solution-explained.md` — resource-by-resource explanation (what + why)
- `azuredeploy/README.md` — usage, parameters, outputs, and deployment guidance

## Why this structure

- Keeps deployable artifacts separate from scripts and docs
- Supports customer handoff with a single, clear template path
- Enables CI quality checks over infrastructure files
