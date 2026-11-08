from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator

# Великі латинські або українські літери чи цифри, дефіс і дві цифри (приклад: КН-31)
GROUP_CODE_PATTERN = r"^[A-ZА-ЯІЇЄҐ0-9]+-[0-9]{2}$"

FullName = Annotated[str, Field(min_length=5, max_length=120)]
GroupCode = Annotated[str, Field(pattern=GROUP_CODE_PATTERN)]
# Індивідуальний варіант 0: рядок від 2 до 100 символів
StudyProgram = Annotated[str, Field(min_length=2, max_length=100)]


class StrictModel(BaseModel):
    """Базова модель, яка не приймає невідомих полів."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class StudentCreate(StrictModel):
    full_name: FullName
    email: EmailStr
    group_code: GroupCode
    study_program: StudyProgram | None = None


class StudentRead(StudentCreate):
    id: UUID


class StudentUpdate(StrictModel):
    full_name: FullName | None = None
    email: EmailStr | None = None
    group_code: GroupCode | None = None
    study_program: StudyProgram | None = None

    @model_validator(mode="after")
    def reject_empty_or_null_update(self) -> "StudentUpdate":
        if not self.model_fields_set:
            raise ValueError("Update body must contain at least one field")
        null_fields = [n for n in self.model_fields_set if getattr(self, n) is None]
        if null_fields:
            raise ValueError(f"Fields cannot be null: {', '.join(sorted(null_fields))}")
        return self