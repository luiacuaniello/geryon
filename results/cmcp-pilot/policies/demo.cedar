// Rule 1: permit calls from the demo-agent workflow.
permit ( principal, action, resource ) when { context.workflow_id == "demo-agent" };

// Rule 2: block a sensitive tool by name, exactly as the quickstart teaches.
forbid ( principal, action, resource ) when { resource.tool_name == "admin.delete_account" };
