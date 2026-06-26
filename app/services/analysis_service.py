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
            run_llm: bool,
            explanation_enabled: bool
    ) -> list[Analysis]:
        """
        Orchestrates the full analysis pipeline in three sequential phases:
        1. Initialize — create Analysis records in DB (sequential, FK-safe)
        2. Execute    — run analyzers in parallel (pure I/O, no DB)
        3. Persist    — save findings to DB (sequential, FK-safe)
        """
        # Filter which analyzers to run this time
        active = self._select_analyzers(run_llm)
        if not active:
            return []

        # Phase 1: DB writes first — guarantee analysis.id exists before findings
        analysis_records = self._initialize_analyses(submission, active, explanation_enabled)

        # Phase 2: parallel I/O — safe because zero DB access inside analyzers
        results = await self._execute_analyzers(
            analysis_records, submission, explanation_enabled
        )

        # Phase 3: sequential DB writes — FK always satisfied
        return self._persist_results(analysis_records, results, explanation_enabled)
    
    def _initialize_analyses(
        self,
        submission: Submission,
        analyzers: list[Analyzer],
        explanation_enabled: bool,
    ) -> list[tuple[Analyzer, Analysis]]:
        """
        Create one Analysis record per analyzer, flushed sequentially.
        Sequential flush guarantees each analysis.id exists in the DB
        before the parallel phase runs and before findings try to reference it.
        """
        records = []
        for analyzer in analyzers:
            analysis = Analysis(
                submission_id=submission.id,
                analyzer_type=analyzer.type,
                status=AnalysisStatus.RUNNING,
                explanation_enabled=explanation_enabled,
                started_at=datetime.now(timezone.utc),
            )
            
            if analyzer.type == AnalyzerType.SEMGREP:
                analysis.ruleset_version = settings.SEMGREP_RULESET
            elif analyzer.type == AnalyzerType.BANDIT:
                analysis.ruleset_version = analyzer.version
            elif analyzer.type == AnalyzerType.LLM:
                analysis.prompt_version = analyzer.version
                analysis.ruleset_version = f"{analyzer.provider}:{analyzer.model}"

            self.session.add(analysis)
            self.session.flush()

            logger.info(
                "analysis_initialized",
                analysis_id=str(analysis.id),
                analyzer=analyzer.name,
            )
            records.append((analyzer, analysis))

        return records
    
    async def _execute_analyzers(
        self,
        records: list[tuple[Analyzer, Analysis]],
        submission: Submission,
        explanation_enabled: bool,
    ) -> list[AnalysisResult]:
        """
        Run all analyzers concurrently via asyncio.gather.
        Safe because analyze() is pure I/O — subprocess or HTTP call.
        No DB access inside this phase.
        """
        logger.info(
            "pipeline_executing",
            submission_id=str(submission.id),
            analyzers=[a.name for a, _ in records],
        )

        return await asyncio.gather(*[
            analyzer.analyze(
                code=submission.code,
                language=submission.language,
                explanation_enabled=explanation_enabled,
            )
            for analyzer, _ in records
        ])

    def _persist_results(
        self,
        records: list[tuple[Analyzer, Analysis]],
        results: list[AnalysisResult],
        explanation_enabled: bool,
    ) -> list[Analysis]:
        """
        Save analyzer results to DB sequentially.
        Sequential flush after each analyzer ensures FK integrity.
        """
        completed = []
        for (analyzer, analysis), result in zip(records, results):
            analysis.completed_at = datetime.now(timezone.utc)

            if result.status == AnalysisStatus.COMPLETED:
                self._persist_findings(analysis, result, explanation_enabled)
                analysis.status = AnalysisStatus.COMPLETED
                logger.info(
                    "analysis_completed",
                    analysis_id=str(analysis.id),
                    analyzer=analyzer.name,
                    findings_count=len(result.findings),
                    duration_ms=result.duration_ms,
                )
            else:
                analysis.status = result.status
                analysis.error_message = result.error_message
                logger.warning(
                    "analysis_failed",
                    analysis_id=str(analysis.id),
                    analyzer=analyzer.name,
                    error=result.error_message,
                    duration_ms=result.duration_ms,
                )

            self.session.flush()  # persist this analysis + its findings
            completed.append(analysis)

        return completed

    def _persist_findings(
        self,
        analysis: Analysis,
        result: AnalysisResult,
        explanation_enabled: bool,
    ) -> None:
        """
        Insert Finding records for a completed analysis.
        Called only from _persist_results — analysis.id is guaranteed to exist.
        """
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
            run_llm: bool,
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
                run_llm=run_llm,
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