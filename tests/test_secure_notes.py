"""Моделі та HTTP-контракт; усі записи вигадані."""

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.schemas.secure_note import NoteCreate


@pytest.mark.parametrize("text", ("x" * 4096, "я" * 2048, "  текст  "))
def test_accepted_text_is_preserved(text):
    assert NoteCreate(text=text).text == text


@pytest.mark.parametrize("payload", (
    {"text": ""}, {"text": " "}, {"text": "x" * 4097},
    {"text": "я" * 2049}, {"text": 42},
    {"text": "demo", "key": "do-not-accept"},
))
def test_invalid_note_input(payload):
    with pytest.raises(ValidationError):
        NoteCreate(**payload)


def test_unknown_student_is_not_found():
    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/students/{uuid4()}/secure-notes/{uuid4()}"
        )
    assert response.status_code == 404


def test_note_api_and_internal_storage():
    # TODO: власна фікстура, наявний студент, чисте сховище, новий ключ на тест.
    # TODO: POST 201 без text/key/конверта, GET 200 із точним текстом.
    # TODO: у внутрішньому EncryptedNote немає text/key; nonce=12, tag=16.
    pytest.fail("Implement API creation, reading and encrypted storage checks")


def test_damaged_note_is_rejected_without_plaintext():
    # TODO: змініть конверт лише в тестовій підготовці, не через HTTP-маршрут.
    # TODO: 500 і detail="Protected note unavailable", без секретів і траси.
    pytest.fail("Implement corrupted stored note acceptance test")


def test_nonce_limit_rejects_only_new_writes():
    # TODO: ліміт 2, третій POST=503; попередній GET=200; не скидати лічильник.
    pytest.fail("Implement nonce usage limit integration test")


def test_benchmark_report_reader():
    # TODO: власні коректні/пошкоджені файли в tmp_path, підміна конфігурації.
    # TODO: 200, 404, 500; API не запускає експеримент і не приймає шлях.
    pytest.fail("Implement fixed-path benchmark report reader checks")


# TODO: регресійні тести всіх маршрутів роботи 1 і тест свого варіанта роботи 2.
