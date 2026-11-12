"""Моделі та HTTP-контракт; усі записи вигадані."""

from dataclasses import replace
import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api import crypto_lab
from app.main import app
from app.repositories.secure_note_repository import repository as note_repository
from app.repositories.student_repository import student_repository
from app.schemas.secure_note import NoteCreate, NoteUpdate
from app.schemas.student import StudentCreate
from app.security.keys import get_process_key, reset_process_key


@pytest.fixture
def clean_env():
    student_repository.clear()
    note_repository.clear()
    reset_process_key(limit=1_000_000)
    yield
    student_repository.clear()
    note_repository.clear()
    reset_process_key(limit=1_000_000)


@pytest.fixture
def sample_student(clean_env):
    return student_repository.create(
        StudentCreate(
            full_name="Іваненко Петро Олександрович",
            email="petro.ivanenko@example.edu.ua",
            group_code="КН-21",
            study_program="Комп'ютерні науки",
        )
    )


@pytest.mark.parametrize("text", ("x" * 4096, "я" * 2048, "  текст  "))
def test_accepted_text_is_preserved(text):
    assert NoteCreate(text=text).text == text
    assert NoteUpdate(text=text).text == text


@pytest.mark.parametrize(
    "payload",
    (
        {"text": ""},
        {"text": " "},
        {"text": "x" * 4097},
        {"text": "я" * 2049},
        {"text": 42},
        {"text": "demo", "key": "do-not-accept"},
    ),
)
def test_invalid_note_input(payload):
    with pytest.raises(ValidationError):
        NoteCreate(**payload)
    with pytest.raises(ValidationError):
        NoteUpdate(**payload)


def test_unknown_student_is_not_found(clean_env):
    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/students/{uuid4()}/secure-notes/{uuid4()}"
        )
    assert response.status_code == 404


def test_note_api_and_internal_storage(sample_student):
    secret_text = "  Службова примітка деканату №42  "
    with TestClient(app) as client:
        create_res = client.post(
            f"/api/v1/students/{sample_student.id}/secure-notes",
            json={"text": secret_text},
        )
        assert create_res.status_code == 201
        meta = create_res.json()
        assert set(meta.keys()) == {"id", "student_id", "algorithm"}
        assert meta["student_id"] == str(sample_student.id)
        assert "text" not in meta
        assert "key" not in meta
        assert "ciphertext" not in meta

        note_id = meta["id"]
        stored = next(iter(note_repository._items.values()))
        assert stored.student_id == sample_student.id
        assert len(stored.nonce) == 12
        assert len(stored.tag) == 16
        assert secret_text.encode("utf-8") not in stored.ciphertext
        assert get_process_key().key not in stored.ciphertext

        read_res = client.get(
            f"/api/v1/students/{sample_student.id}/secure-notes/{note_id}"
        )
        assert read_res.status_code == 200
        body = read_res.json()
        assert body == {
            "id": note_id,
            "student_id": str(sample_student.id),
            "algorithm": meta["algorithm"],
            "text": secret_text,
        }


def test_foreign_student_note_returns_404(sample_student):
    other_student = student_repository.create(
        StudentCreate(
            full_name="Коваленко Олена Сергіївна",
            email="olena.kovalenko@example.edu.ua",
            group_code="КН-22",
        )
    )
    with TestClient(app) as client:
        create_res = client.post(
            f"/api/v1/students/{sample_student.id}/secure-notes",
            json={"text": "Конфіденційна інформація"},
        )
        note_id = create_res.json()["id"]

        foreign_get = client.get(
            f"/api/v1/students/{other_student.id}/secure-notes/{note_id}"
        )
        assert foreign_get.status_code == 404


def test_damaged_note_is_rejected_without_plaintext(sample_student):
    secret_text = "Секретний запис для перевірки цілісності"
    with TestClient(app) as client:
        create_res = client.post(
            f"/api/v1/students/{sample_student.id}/secure-notes",
            json={"text": secret_text},
        )
        note_id = create_res.json()["id"]
        stored_uuid = next(iter(note_repository._items.keys()))
        original = note_repository._items[stored_uuid]

        tampered_ct = bytes([original.ciphertext[0] ^ 0xFF]) + original.ciphertext[1:]
        note_repository._items[stored_uuid] = replace(original, ciphertext=tampered_ct)

        res = client.get(
            f"/api/v1/students/{sample_student.id}/secure-notes/{note_id}"
        )
        assert res.status_code == 500
        assert res.json() == {"detail": "Protected note unavailable"}
        assert secret_text not in res.text
        assert "Traceback" not in res.text


def test_nonce_limit_rejects_only_new_writes(sample_student):
    reset_process_key(limit=2)
    with TestClient(app) as client:
        r1 = client.post(
            f"/api/v1/students/{sample_student.id}/secure-notes",
            json={"text": "Перша примітка"},
        )
        r2 = client.post(
            f"/api/v1/students/{sample_student.id}/secure-notes",
            json={"text": "Друга примітка"},
        )
        assert r1.status_code == 201
        assert r2.status_code == 201

        r3 = client.post(
            f"/api/v1/students/{sample_student.id}/secure-notes",
            json={"text": "Третя примітка"},
        )
        assert r3.status_code == 503
        assert r3.json() == {"detail": "Protected note unavailable"}

        note_id_1 = r1.json()["id"]
        get_old = client.get(
            f"/api/v1/students/{sample_student.id}/secure-notes/{note_id_1}"
        )
        assert get_old.status_code == 200
        assert get_old.json()["text"] == "Перша примітка"


def test_variant_0_patch_updates_note_with_fresh_nonce(sample_student):
    other_student = student_repository.create(
        StudentCreate(
            full_name="Сидоренко Андрій Ігорович",
            email="andrii.sydorenko@example.edu.ua",
            group_code="КН-23",
        )
    )
    with TestClient(app) as client:
        create_res = client.post(
            f"/api/v1/students/{sample_student.id}/secure-notes",
            json={"text": "Початковий текст"},
        )
        assert create_res.status_code == 201
        note_id = create_res.json()["id"]
        stored_uuid = next(iter(note_repository._items.keys()))
        old_envelope = note_repository._items[stored_uuid]

        foreign_patch = client.patch(
            f"/api/v1/students/{other_student.id}/secure-notes/{note_id}",
            json={"text": "Спроба підміни"},
        )
        assert foreign_patch.status_code == 404