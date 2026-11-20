import { useLocation } from "@tanstack/react-router";
import { investigationContext, investigationWorkspaceRequested } from "./investigation-context";
import { InvestigationWorkspacePage } from "./investigation-workspace";
import { CaseListPage } from "./cases";

/**
 * Without a context, `/investigations` is the case list. Any supported exact
 * investigation context opens the workspace that consumes those parameters.
 */
export function InvestigationsRoutePage() {
  const location = useLocation();
  const parameters = new URLSearchParams(location.searchStr);
  let workspaceRequested = true;
  try {
    workspaceRequested = investigationWorkspaceRequested(investigationContext(parameters));
  } catch {
    // The workspace renders a visible error and deliberately makes no broad request.
  }
  return workspaceRequested ? <InvestigationWorkspacePage/> : <CaseListPage/>;
}
