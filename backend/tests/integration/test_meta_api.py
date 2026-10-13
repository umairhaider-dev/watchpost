from __future__ import annotations

from httpx import AsyncClient

from watchpost.events import FIELDS


async def test_lists_every_normalised_field(client: AsyncClient) -> None:
    response = await client.get("/api/meta/fields")

    assert response.status_code == 200
    body = response.json()
    assert [field["name"] for field in body] == [spec.name for spec in FIELDS]
    source_ip = next(field for field in body if field["name"] == "source.ip")
    assert source_ip["kind"] == "ip"
    assert source_ip["description"]
