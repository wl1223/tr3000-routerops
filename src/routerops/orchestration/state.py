from routerops.models import WorkflowState

TRANSITIONS: dict[WorkflowState, set[WorkflowState]] = {
    WorkflowState.RECEIVED: {WorkflowState.DISCOVERY, WorkflowState.FAILED_SAFE},
    WorkflowState.DISCOVERY: {WorkflowState.DIAGNOSIS, WorkflowState.FAILED_SAFE},
    WorkflowState.DIAGNOSIS: {WorkflowState.PLAN, WorkflowState.SUCCEEDED, WorkflowState.FAILED_SAFE},
    WorkflowState.PLAN: {WorkflowState.POLICY_CHECK, WorkflowState.FAILED_SAFE},
    WorkflowState.POLICY_CHECK: {
        WorkflowState.WAITING_APPROVAL,
        WorkflowState.EXECUTING,
        WorkflowState.FAILED_SAFE,
    },
    WorkflowState.WAITING_APPROVAL: {WorkflowState.EXECUTING, WorkflowState.FAILED_SAFE},
    WorkflowState.EXECUTING: {WorkflowState.VERIFYING, WorkflowState.ROLLING_BACK},
    WorkflowState.VERIFYING: {
        WorkflowState.SUCCEEDED,
        WorkflowState.ROLLING_BACK,
        WorkflowState.FAILED_SAFE,
    },
    WorkflowState.ROLLING_BACK: {WorkflowState.ROLLED_BACK, WorkflowState.FAILED_SAFE},
    WorkflowState.SUCCEEDED: set(),
    WorkflowState.ROLLED_BACK: set(),
    WorkflowState.FAILED_SAFE: set(),
}


class StateMachine:
    def __init__(self) -> None:
        self.state = WorkflowState.RECEIVED

    def transition(self, target: WorkflowState) -> None:
        if target not in TRANSITIONS[self.state]:
            raise ValueError(f"invalid workflow transition: {self.state} -> {target}")
        self.state = target

