from uuid import UUID, uuid4

from app.schemas.student import StudentCreate, StudentRead, StudentUpdate


class StudentNotFoundError(KeyError):
    """Запис студента не знайдено."""


class DuplicateEmailError(ValueError):
    """Електронна адреса вже використовується."""


class InMemoryStudentRepository:
    def __init__(self) -> None:
        self._students: dict[UUID, StudentRead] = {}

    def _ensure_email_free(self, email: str, exclude_id: UUID | None = None) -> None:
        wanted = str(email).lower()
        for student in self._students.values():
            if student.id != exclude_id and str(student.email).lower() == wanted:
                raise DuplicateEmailError(wanted)

    def create(self, payload: StudentCreate) -> StudentRead:
        self._ensure_email_free(payload.email)
        student = StudentRead(id=uuid4(), **payload.model_dump())
        self._students[student.id] = student
        return student

    def list(self, *, study_program: str | None = None) -> list[StudentRead]:
        students = [s for s in self._students.values()]
        if study_program is not None:
            wanted = study_program.strip().casefold()
            students = [
                s for s in students
                if s.study_program is not None and s.study_program.casefold() == wanted
            ]
        return students

    def get(self, student_id: UUID) -> StudentRead:
        try:
            return self._students[student_id]
        except KeyError:
            raise StudentNotFoundError(str(student_id)) from None

    def update(self, student_id: UUID, payload: StudentUpdate) -> StudentRead:
        current = self.get(student_id)
        changes = payload.model_dump(exclude_unset=True)
        if "email" in changes:
            self._ensure_email_free(changes["email"], exclude_id=student_id)
        updated = current.model_copy(update=changes)
        self._students[student_id] = updated
        return updated

    def clear(self) -> None:
        self._students.clear()


student_repository = InMemoryStudentRepository()