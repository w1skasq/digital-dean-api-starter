"""Каркас маршрутів приміток; не підключений до наявного app/main.py."""

from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/students", tags=["secure-notes"])

# TODO: POST /{student_id}/secure-notes, 201 із NoteMetadata, без text і ключа.
# TODO: GET /{student_id}/secure-notes/{note_id}, 200 із перевіреним NoteRead.
# TODO: використайте наявний репозиторій студентів, не створюйте другий API.
# TODO: 404 для невідомого студента/примітки або чужого студентського ресурсу.
# TODO: 422 для неправильного UUID, тексту й невідомих полів.
# TODO: пошкоджений серверний конверт: 500, detail="Protected note unavailable".
# TODO: межа лічильника: 503 із тим самим detail; старі примітки ще читаються.
# TODO: не видавайте відкритий текст до перевірки тега і очікуваного контексту.
# TODO: один ProcessKey на процес, один NonceSequence на цей ключ.
# TODO: підключіть router у своєму main.py лише разом з реалізацією.
