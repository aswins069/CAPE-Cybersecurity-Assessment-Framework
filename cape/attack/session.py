"""Attack session manager - handles session lifecycle and persistence."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Optional
from uuid import UUID

from cape.attack.models import AttackSession, Evidence
from cape.shared.enums import SessionState

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages attack session state machine and persistence.

    Handles all state transitions and persists session data to the database.
    """

    def create_session(
        self,
        target: str,
        plan_id: UUID,
        operator: str,
        scope_token: str,
    ) -> AttackSession:
        """Create a new attack session in IDLE state.

        Args:
            target: Target being assessed.
            plan_id: ID of the attack plan.
            operator: Operator name.
            scope_token: Scope authorization token.

        Returns:
            New AttackSession in IDLE state.
        """
        session = AttackSession(
            id=uuid.uuid4(),
            target=target,
            plan_id=plan_id,
            state=SessionState.IDLE,
            operator=operator,
            scope_token=scope_token,
            started_at=datetime.utcnow(),
        )
        self._persist_session(session)
        return session

    def load_session(self, session_id: UUID) -> Optional[AttackSession]:
        """Load an existing session from the database.

        Args:
            session_id: UUID of session to load.

        Returns:
            AttackSession or None if not found.
        """
        try:
            from cape.db.session import db_session
            from cape.db.models import AttackSessionModel

            with db_session() as s:
                row = s.query(AttackSessionModel).filter_by(id=str(session_id)).first()
                if not row:
                    return None
                return AttackSession(
                    id=UUID(row.id),
                    target=row.target,
                    plan_id=UUID(row.plan_id),
                    state=SessionState(row.state),
                    selected_modules=row.selected_modules or [],
                    started_at=row.started_at,
                    completed_at=row.completed_at,
                    operator=row.operator,
                    scope_token=row.scope_token,
                    steps_completed=[UUID(s) for s in (row.steps_completed or [])],
                    notes=row.notes or "",
                )
        except Exception as e:
            logger.error(f"Failed to load session {session_id}: {e}")
            return None

    def transition(self, session: AttackSession, new_state: SessionState) -> None:
        """Transition session to a new state.

        Args:
            session: Session to transition.
            new_state: Target state.

        Raises:
            ValueError: If transition is invalid.
        """
        old_state = session.state
        session.transition_to(new_state)

        if new_state == SessionState.COMPLETED:
            session.completed_at = datetime.utcnow()

        logger.info(
            f"Session {session.id}: {old_state.value} → {new_state.value} "
            f"[operator={session.operator}]"
        )
        self._persist_session(session)

    def mark_step_complete(self, session: AttackSession, step_id: UUID) -> None:
        """Record a completed step in the session.

        Args:
            session: Active session.
            step_id: UUID of completed step.
        """
        if step_id not in session.steps_completed:
            session.steps_completed.append(step_id)
        self._persist_session(session)

    def add_evidence(self, session: AttackSession, evidence: Evidence) -> None:
        """Add evidence to session and persist.

        Args:
            session: Active session.
            evidence: Evidence item to add.
        """
        session.evidence.append(evidence)
        self._persist_evidence(evidence)

    def _persist_session(self, session: AttackSession) -> None:
        """Save session to database."""
        try:
            from cape.db.session import db_session
            from cape.db.models import AttackSessionModel

            with db_session() as s:
                row = AttackSessionModel(
                    id=str(session.id),
                    target=session.target,
                    plan_id=str(session.plan_id),
                    state=session.state.value,
                    selected_modules=session.selected_modules,
                    started_at=session.started_at,
                    completed_at=session.completed_at,
                    operator=session.operator,
                    scope_token=session.scope_token,
                    steps_completed=[str(sid) for sid in session.steps_completed],
                    notes=session.notes,
                )
                s.merge(row)
        except Exception as e:
            logger.error(f"Failed to persist session: {e}")

    def _persist_evidence(self, evidence: Evidence) -> None:
        """Save evidence to database."""
        try:
            from cape.db.session import db_session
            from cape.db.models import EvidenceModel

            with db_session() as s:
                row = EvidenceModel(
                    id=str(evidence.id),
                    session_id=str(evidence.session_id),
                    step_id=str(evidence.step_id),
                    timestamp=evidence.timestamp,
                    tool=evidence.tool,
                    command_run=evidence.command_run,
                    raw_output_file=str(evidence.raw_output_file),
                    summary=evidence.summary,
                    finding_ids=[str(f) for f in evidence.finding_ids],
                )
                s.merge(row)
        except Exception as e:
            logger.error(f"Failed to persist evidence: {e}")
