# Створіть тести для таких випадків:
# 1. успішне створення запису;
# 2. відхилення некоректних даних;
# 3. отримання списку;
# 4. отримання наявного запису;
# 5. відповідь 404 для відсутнього запису;
# 6. часткове оновлення;
# 7. відхилення невідомого поля;
# 8. фільтрація за полем індивідуального варіанта;
# 9–10. щонайменше дві додаткові перевірки поля варіанта.
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.repositories.student_repository import student_repository

client = TestClient(app)
BASE = "/api/v1/students"

VALID = {
    "full_name": "Олена Коваль",
    "email": "olena.koval@example.com",
    "group_code": "КН-31",
    "study_program": "Кібербезпека",
}


@pytest.fixture(autouse=True)
def clean_repository():
    student_repository.clear()
    yield
    student_repository.clear()


def create(**overrides):
    return client.post(BASE, json={**VALID, **overrides})


def test_create_student():
    response = create()
    assert response.status_code == 201
    body = response.json()
    assert UUID(body["id"])
    for key, value in VALID.items():
        assert body[key] == value


def test_invalid_email_rejected_and_not_created():
    response = create(email="not-an-email")
    assert response.status_code == 422
    assert client.get(BASE).json() == []


def test_list_students():
    create()
    create(email="ivan.petrenko@example.com", full_name="Іван Петренко")
    response = client.get(BASE)
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_get_existing_student():
    created = create().json()
    response = client.get(f"{BASE}/{created['id']}")
    assert response.status_code == 200
    assert response.json() == created


def test_get_missing_student_returns_404():
    response = client.get(f"{BASE}/{uuid4()}")
    assert response.status_code == 404
    assert "Traceback" not in response.text


def test_partial_update_keeps_other_fields():
    created = create().json()
    response = client.patch(f"{BASE}/{created['id']}", json={"group_code": "КН-32"})
    assert response.status_code == 200
    body = response.json()
    assert body["group_code"] == "КН-32"
    for key in ("id", "full_name", "email", "study_program"):
        assert body[key] == created[key]


def test_unknown_field_rejected():
    created = create().json()
    response = client.patch(f"{BASE}/{created['id']}", json={"is_admin": True})
    assert response.status_code == 422


def test_empty_patch_rejected():
    created = create().json()
    response = client.patch(f"{BASE}/{created['id']}", json={})
    assert response.status_code == 422


def test_id_cannot_be_changed():
    created = create().json()
    response = client.patch(f"{BASE}/{created['id']}", json={"id": str(uuid4())})
    assert response.status_code == 422


def test_duplicate_email_on_create_returns_409():
    create()
    response = create(email="OLENA.KOVAL@example.com")
    assert response.status_code == 409


def test_duplicate_email_on_patch_returns_409():
    create()
    second = create(email="ivan.petrenko@example.com").json()
    response = client.patch(f"{BASE}/{second['id']}", json={"email": VALID["email"]})
    assert response.status_code == 409


def test_patch_own_email_is_allowed():
    created = create().json()
    response = client.patch(f"{BASE}/{created['id']}", json={"email": VALID["email"]})
    assert response.status_code == 200


# --- Індивідуальний варіант 0: study_program ---

def test_filter_by_study_program():
    create()
    create(email="ivan.petrenko@example.com", study_program="Інженерія ПЗ")
    response = client.get(BASE, params={"study_program": "кібербезпека"})
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 1
    assert all(item["study_program"] == "Кібербезпека" for item in items)


@pytest.mark.parametrize("value", ["ІТ", "А" * 100])
def test_study_program_boundary_accepted(value):
    assert create(study_program=value).status_code == 201


@pytest.mark.parametrize("value", ["А", "А" * 101])
def test_study_program_boundary_rejected(value):
    assert create(study_program=value).status_code == 422