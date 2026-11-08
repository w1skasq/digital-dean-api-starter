from fastapi import APIRouter


router = APIRouter(prefix="/api/v1/students", tags=["students"])

# TODO 1: реалізуйте POST /api/v1/students.
# TODO 2: реалізуйте GET /api/v1/students.
# TODO 3: реалізуйте GET /api/v1/students/{student_id}.
# TODO 4: після базової версії додайте PATCH /api/v1/students/{student_id}.
# TODO 5: перетворюйте помилки репозиторію на визначені HTTP-відповіді.
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from app.repositories.student_repository import (
    DuplicateEmailError,
    StudentNotFoundError,
    student_repository,
)
from app.schemas.student import StudentCreate, StudentRead, StudentUpdate

router = APIRouter(prefix="/api/v1/students", tags=["students"])


@router.post(
    "",
    response_model=StudentRead,
    status_code=status.HTTP_201_CREATED,
    responses={409: {"description": "Email already exists"}},
)
def create_student(payload: StudentCreate) -> StudentRead:
    try:
        return student_repository.create(payload)
    except DuplicateEmailError:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Email already exists") from None


@router.get("", response_model=list[StudentRead])
def list_students(
    study_program: Annotated[str | None, Query(min_length=2, max_length=100)] = None,
) -> list[StudentRead]:
    return student_repository.list(study_program=study_program)


@router.get(
    "/{student_id}",
    response_model=StudentRead,
    responses={404: {"description": "Student not found"}},
)
def get_student(student_id: UUID) -> StudentRead:
    try:
        return student_repository.get(student_id)
    except StudentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Student not found") from None


@router.patch(
    "/{student_id}",
    response_model=StudentRead,
    responses={404: {"description": "Student not found"}, 409: {"description": "Email already exists"}},
)
def update_student(student_id: UUID, payload: StudentUpdate) -> StudentRead:
    try:
        return student_repository.update(student_id, payload)
    except StudentNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Student not found") from None
    except DuplicateEmailError:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Email already exists") from None