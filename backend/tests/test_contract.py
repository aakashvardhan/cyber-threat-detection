"""Checks the backend against docs/api/openapi.yaml (or OPENAPI_SPEC) when the spec is available."""
import os
from pathlib import Path

import pytest

from app import schemas
from app.main import create_app

yaml = pytest.importorskip("yaml")
SPEC_PATH = Path(os.environ.get("OPENAPI_SPEC", Path(__file__).resolve().parents[2] / "docs" / "api" / "openapi.yaml"))
pytestmark = pytest.mark.skipif(not SPEC_PATH.exists(), reason=f"no API spec at {SPEC_PATH}")


@pytest.fixture(scope="module")
def spec():
    return yaml.safe_load(SPEC_PATH.read_text())


def test_every_spec_operation_is_implemented(spec, make_settings):
    app = create_app(make_settings())
    implemented = {(route.path, method.lower()) for route in app.routes for method in getattr(route, "methods", [])}
    for path, operations in spec["paths"].items():
        for method in operations:
            if method in {"get", "post", "patch", "put", "delete"}:
                assert (path, method) in implemented, f"{method.upper()} {path} is not implemented"


@pytest.mark.parametrize("name", ["DetectResponse", "ReplayState", "WindowStats", "EdgePreview", "IncidentSummary",
                                  "IncidentList", "MitreCandidate", "TacticPrediction", "Edge", "Evidence",
                                  "Sentence", "Explanation", "RetrievalSource", "RetrievalTrace", "Mitigation",
                                  "ModelOutput", "ActivityEntry", "IncidentUpdate", "DetectRequest", "Error"])
def test_schema_fields_match(spec, name):
    schema = spec["components"]["schemas"][name]
    model = getattr(schemas, name)
    spec_fields = set(schema.get("properties", {}))
    assert spec_fields <= set(model.model_fields), f"{name} lacks {spec_fields - set(model.model_fields)}"
    for field in schema.get("required", []):
        assert model.model_fields[field].is_required() or field in getattr(model, "NULLABLE", ()) \
            or model.model_fields[field].default is not None, f"{name}.{field} is required by the spec"


def test_incident_detail_has_all_spec_fields(spec):
    parts = spec["components"]["schemas"]["IncidentDetail"]["allOf"]
    extra = parts[1]
    assert set(extra["properties"]) <= set(schemas.IncidentDetail.model_fields)
