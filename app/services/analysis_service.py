from sqlmodel import Session, select
from uuid import UUID
import asyncio
from datetime import datetime, timezone

from app.analyzers.port import Analyzer, AnalysisResult
from app.core.logging import get_logger
from app.services.audit_service import AuditService
from app.models import (
    Submission, 
    Analysis, 
    AnalyzerType, 
    AnalysisStatus,
    Finding,
    User,
    EventType
)
from app.core.config import settings

logger = get_logger(__name__)

class SubmissionRepository:
    def __init__(self, session):
        self.session = session

    def create(self, code: str, language: str, user_id: UUID) -> Submission:
        submission = Submission(user_id=user_id, code=code, language=language)
        self.session.add(submission)
        self.session.flush()  # Populates submission.id without breaking transaction borders
        
        logger.info("submission_created", submission_id=str(submission.id), user_id=str(user_id))
        return submission
    
class AnalysisOrchestrator:
    def __init__(self, session: Session, analyzers: list[Analyzer]):
        self.session = session
        self.analyzers = analyzers
    
    async def run_pipeline(
            self,
            submission: Submission,
            explanation_enabled: bool
    ) -> list[Analysis]:
        """Executes all valid analyzers concurrently to save time"""
        tasks=[]
        for analyzer in self.analyzers:
            # schedule the task for parallel execution
            tasks.append(
                self._run_analyzer(
                    submission=submission,
                    analyzer=analyzer,
                    explanation_enabled=explanation_enabled
                )
            )

        # Fire all analyzer executions together
        return await asyncio.gather(*tasks)
    
    async def _run_analyzer(
            self,
            submission: Submission,
            analyzer: Analyzer,
            explanation_enabled: bool
    ) -> Analysis:
        """Executes a single analyzer within an isolated operational tracking block"""

        # 1. Initialize tracking record with RUNNING status
        analysis = Analysis(
            submission_id=submission.id,
            analyzer_type=analyzer.type,
            status=AnalysisStatus.RUNNING,
            explanation_enabled=explanation_enabled,
            started_at=datetime.now(timezone.utc)
        )
        if analyzer.type == AnalyzerType.SEMGREP:
            analysis.ruleset_version = settings.SEMGREP_RULESET
        elif analyzer.type == AnalyzerType.LLM:
            analysis.prompt_version = analyzer.version
        
        self.session.add(analysis)
        self.session.flush()

        logger.info(
            "analysis_started",
            analysis_id=str(analysis.id),
            analyzer=analyzer.name,
        )

        try:
            # 2. Fire the async port operation safely
            # Match the signature constraints for LLM or SEMGREP
            if analyzer.type == AnalyzerType.LLM:
                result: AnalysisResult = await analyzer.analyze(
                    code=submission.code,
                    language=submission.language,
                    explanation_enabled=explanation_enabled
                )
            else:
                result: AnalysisResult = await analyzer.analyze(
                    code = submission.code,
                    language=submission.language,
                    explanation_enabled=False
                )
            
            # 3. Process Execution Timelines
            analysis.completed_at = datetime.now(timezone.utc)

            # Check mapping status according to ADR-003
            if result.status == AnalysisStatus.COMPLETED:
                analysis.status = AnalysisStatus.COMPLETED

                # Append structural database elements safely
                for f in result.findings:
                    finding = Finding(
                        analysis_id=analysis.id,
                        severity=f.severity,
                        line_number=f.line_number,
                        rule_id=f.rule_id,
                        message=f.message,
                        explanation=f.explanation if explanation_enabled else None
                    )
                    self.session.add(finding)
                
                logger.info(
                    "analysis_completed",
                    analysis_id=str(analysis.id),
                    findings_count=len(result.findings),
                    duration_ms=result.duration_ms,
                )
                
            else:
                # Captures both FAILED and ERROR processing states
                analysis.status = result.status
                analysis.error_message = result.error_message

                # Process partial findings if it was a FAILED state (as discussed in Scenario A)
                if result.findings:
                    for f in result.findings:
                        finding = Finding(
                            analysis_id=analysis.id,
                            severity=f.severity,
                            line_number=f.line_number,
                            rule_id=f.rule_id,
                            message=f.message,
                            explanation=f.explanation if explanation_enabled else None,
                        )
                        self.session.add(finding)

                logger.warning(
                    "analysis_execution_issue",
                    analysis_id=str(analysis.id),
                    status=result.status,
                    error=result.error_message,
                )

            # Flush changes for this individual task to the DB staging area
            self.session.flush()
            return analysis

        except Exception as e:
            # Absolute boundary shield block: prevents a total code crash from breaking 
            # parallel concurrent sister execution threads.
            analysis.completed_at = datetime.now(timezone.utc)
            analysis.status = AnalysisStatus.ERROR
            analysis.error_message = f"Unexpected runtime orchestrator failure: {str(e)}"
            logger.exception("analysis_orchestration_system_crash", analysis_id=str(analysis.id))

class AnalysisService:
    def __init__(
            self,
            repo: SubmissionRepository,
            orchestrator: AnalysisOrchestrator, 
            session: Session
    ):
        self.session = session
        self.repo = repo
        self.orchestrator = orchestrator
        self.audit = AuditService(session)

    async def create_and_analyze(
            self,
            code: str,
            language: str,
            user: User,
            explanation_enabled: bool = False
    ):
        """
        Executes a pipeline submission and triggers concurrent analytics tracking
        """
        # Step 1: create submission
        submission = self.repo.create(
            code=code,
            language=language,
            user_id=user.id
        )

        try:
            # Step 2: Delegate parallel analyzers execution to the orchestrator
            analysis_records = await self.orchestrator.run_pipeline(
                submission=submission,
                explanation_enabled=explanation_enabled
            )

            # Step 3: Log security context
            self.audit.log(
                user_id=user.id,
                event_type=EventType.SUBMISSION_CREATED,
                details={"submission_id": str(submission.id)}
            )

            self.session.commit()
            self.session.refresh(submission)

            return submission, analysis_records
        
        except Exception as e:
            # Step 4: Protect DB state isolation integrity if an orchestration error pops
            logger.error(
                "analysis_pipeline_aborted", 
                submission_id=str(submission.id), 
                error=str(e)
            )
            self.session.rollback()
            raise

    def get_submission_with_analyses(self, submission_id: UUID) -> dict:
        """Load a submission with all its analyses and findings."""
        submission = self.session.get(Submission, submission_id)
        if not submission:
            return None

        analyses = self.session.exec(
            select(Analysis).where(Analysis.submission_id == submission_id)
        ).all()

        result = {
            "id": str(submission.id),
            "language": submission.language,
            "source_mode": submission.source_mode,
            "created_at": submission.created_at.isoformat(),
            "analyses": [],
        }

        for analysis in analyses:
            findings = self.session.exec(
                select(Finding).where(Finding.analysis_id == analysis.id)
            ).all()

            result["analyses"].append({
                "id": str(analysis.id),
                "analyzer_type": analysis.analyzer_type.value,
                "status": analysis.status.value,
                "findings_count": len(findings),
                "error_message": analysis.error_message,
                "duration_ms": (
                    int((analysis.completed_at - analysis.started_at).total_seconds() * 1000)
                    if analysis.completed_at and analysis.started_at
                    else None
                ),
                "findings": [
                    {
                        "id": str(f.id),
                        "severity": f.severity.value,
                        "line_number": f.line_number,
                        "rule_id": f.rule_id,
                        "message": f.message,
                        "explanation": f.explanation,
                        "status": f.status.value,
                    }
                    for f in findings
                ],
            })

        return result