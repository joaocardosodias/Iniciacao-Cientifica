import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import yaml

from src.context_modes import (
    PROMPT_TEMPLATE_VERSION,
    build_global_context,
    context_visibility,
    validate_context_mode,
)
from src.trace import write_json_atomic


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Documento YAML deve ser um objeto: {path}")
    return value


def condition_context_mode(protocol: dict[str, Any], condition: str) -> str:
    conditions = protocol.get("conditions") or []
    matches = [
        item
        for item in conditions
        if isinstance(item, dict) and item.get("id") == condition
    ]
    if len(matches) != 1:
        raise ValueError("A condicao deve aparecer exatamente uma vez no protocolo.")
    mode = matches[0].get("context_mode")
    if not isinstance(mode, str):
        raise ValueError("A condicao precisa definir context_mode.")
    return validate_context_mode(mode)


def protocol_condition_ids(protocol: dict[str, Any]) -> list[str]:
    conditions = protocol.get("conditions") or []
    identifiers = []
    for item in conditions:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError("Cada condicao do protocolo precisa ter id.")
        identifier = item["id"].strip()
        if not identifier:
            raise ValueError("O id de uma condicao nao pode ser vazio.")
        condition_context_mode(protocol, identifier)
        identifiers.append(identifier)
    if not identifiers:
        raise ValueError("O protocolo precisa definir ao menos uma condicao.")
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("O protocolo possui condicoes duplicadas.")
    return identifiers


def validate_protocol(
    protocol: dict[str, Any],
    experiment_id: str,
    condition: str,
    scenario: str,
    planned_replicates: int,
    requested_model: str,
    resolved_model: str,
    provider: str,
    inference_provider: str | None,
    generation_parameters: dict[str, Any],
    context_mode: str,
) -> None:
    if protocol.get("status") != "frozen":
        raise ValueError("O protocolo precisa ter status: frozen.")
    experiment = protocol.get("experiment") or {}
    if experiment.get("id") != experiment_id:
        raise ValueError("O id do protocolo difere de --experiment-id.")
    if experiment.get("scenario") != scenario:
        raise ValueError("O cenario do protocolo difere de --scenario.")
    if experiment.get("planned_replicates") != planned_replicates:
        raise ValueError("O numero de replicas difere do protocolo.")
    declared_context_mode = condition_context_mode(protocol, condition)
    if declared_context_mode != validate_context_mode(context_mode):
        raise ValueError("O context_mode executado difere da condicao do protocolo.")
    if not protocol.get("hypothesis"):
        raise ValueError("O protocolo precisa definir hypothesis.")
    if not protocol.get("primary_metric"):
        raise ValueError("O protocolo precisa definir primary_metric.")
    if not protocol.get("exclusion_criteria"):
        raise ValueError("O protocolo precisa definir exclusion_criteria.")
    models = protocol.get("models") or []
    model_match = any(
        isinstance(item, dict)
        and item.get("model") in {requested_model, resolved_model}
        and item.get("provider") == (inference_provider or provider)
        for item in models
    )
    if not model_match:
        raise ValueError("O modelo e o provider nao correspondem ao protocolo.")
    declared_parameters = protocol.get("generation_parameters") or {}
    for key in ("temperature", "top_p", "seed", "max_tokens"):
        if declared_parameters.get(key) != generation_parameters.get(key):
            raise ValueError(f"O parametro {key} difere do protocolo.")


def validate_rubric(rubric: dict[str, Any]) -> None:
    if not rubric.get("version"):
        raise ValueError("A rubrica precisa definir version.")
    functional = rubric.get("functional_statuses") or {}
    required = {
        "passed",
        "partial",
        "failed",
        "inconclusive",
        "not_run",
        "environment_error",
    }
    if not required.issubset(functional):
        raise ValueError("A rubrica nao define todos os estados funcionais.")
    classifications = set(rubric.get("component_classifications") or [])
    expected = {
        "accepted",
        "explicit_refusal",
        "implicit_refusal",
        "empty_response",
        "invalid_code",
        "prototype_mismatch",
        "inert_implementation",
        "valid_component",
    }
    if not expected.issubset(classifications):
        raise ValueError("A rubrica nao define todas as classificacoes de componente.")


def freeze_experimental_inputs(
    campaign_root: Path,
    scenario: str,
    scenario_description: str,
    scenario_config_h: str,
    scenario_components: list[dict[str, Any]],
    scenario_main_c: str,
    protocol_path: Path,
    rubric_path: Path,
    experiment_id: str,
    condition: str,
    planned_replicates: int,
    requested_model: str,
    resolved_model: str,
    provider: str,
    inference_provider: str | None,
    generation_parameters: dict[str, Any],
    context_mode: str,
) -> dict[str, Any]:
    protocol_path = protocol_path.resolve()
    rubric_path = rubric_path.resolve()
    if not protocol_path.is_file():
        raise FileNotFoundError(f"Protocolo nao encontrado: {protocol_path}")
    if not rubric_path.is_file():
        raise FileNotFoundError(f"Rubrica nao encontrada: {rubric_path}")
    protocol = load_yaml(protocol_path)
    rubric = load_yaml(rubric_path)
    validate_protocol(
        protocol,
        experiment_id,
        condition,
        scenario,
        planned_replicates,
        requested_model,
        resolved_model,
        provider,
        inference_provider,
        generation_parameters,
        context_mode,
    )
    validate_rubric(rubric)
    components_hash = sha256_bytes(canonical_bytes(scenario_components))
    config_hash = sha256_bytes(scenario_config_h.encode("utf-8"))
    main_hash = sha256_bytes(scenario_main_c.encode("utf-8"))
    identity = {
        "schema_version": "1.0",
        "scenario": scenario,
        "scenario_description": scenario_description,
        "component_count": len(scenario_components),
        "components": scenario_components,
        "config_h": scenario_config_h,
        "main_c": scenario_main_c,
        "hashes": {
            "components_sha256": components_hash,
            "config_sha256": config_hash,
            "main_sha256": main_hash,
        },
    }
    stimulus_hash = sha256_bytes(canonical_bytes(identity))
    identity["stimulus_sha256"] = stimulus_hash
    inputs_dir = campaign_root / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    global_context = build_global_context(
        scenario_description,
        scenario_components,
        scenario_config_h,
        scenario_main_c,
    )
    intervention = {
        "schema_version": "1.0",
        "context_mode": validate_context_mode(context_mode),
        "prompt_template_version": PROMPT_TEMPLATE_VERSION,
        "visibility": context_visibility(context_mode),
        "full_context_sha256": sha256_bytes(global_context.encode("utf-8")),
    }
    intervention_hash = sha256_bytes(canonical_bytes(intervention))
    intervention["intervention_sha256"] = intervention_hash
    write_json_atomic(inputs_dir / "scenario_snapshot.json", identity)
    write_json_atomic(inputs_dir / "intervention.json", intervention)
    shutil.copy2(protocol_path, inputs_dir / "protocol.yaml")
    shutil.copy2(rubric_path, inputs_dir / "rubric.yaml")
    return {
        "stimulus_sha256": stimulus_hash,
        "stimulus_path": "inputs/scenario_snapshot.json",
        "protocol_sha256": sha256_file(inputs_dir / "protocol.yaml"),
        "protocol_path": "inputs/protocol.yaml",
        "protocol_version": protocol.get("version"),
        "rubric_sha256": sha256_file(inputs_dir / "rubric.yaml"),
        "rubric_path": "inputs/rubric.yaml",
        "rubric_version": rubric.get("version"),
        "context_mode": context_mode,
        "intervention_sha256": intervention_hash,
        "intervention_path": "inputs/intervention.json",
        "prompt_template_version": PROMPT_TEMPLATE_VERSION,
        "full_context_sha256": intervention["full_context_sha256"],
    }


def load_frozen_inputs(campaign_root: Path, campaign: dict[str, Any]) -> dict[str, Any]:
    paths = {
        "stimulus": campaign_root / campaign.get("stimulus_path", "inputs/scenario_snapshot.json"),
        "protocol": campaign_root / campaign.get("protocol_path", "inputs/protocol.yaml"),
        "rubric": campaign_root / campaign.get("rubric_path", "inputs/rubric.yaml"),
        "intervention": campaign_root / campaign.get(
            "intervention_path", "inputs/intervention.json"
        ),
    }
    for path in paths.values():
        if not path.is_file():
            raise FileNotFoundError(f"Entrada congelada ausente: {path}")
    stimulus = json.loads(paths["stimulus"].read_text(encoding="utf-8"))
    intervention = json.loads(paths["intervention"].read_text(encoding="utf-8"))
    declared_stimulus = stimulus.pop("stimulus_sha256", None)
    declared_intervention = intervention.pop("intervention_sha256", None)
    observed = {
        "stimulus_sha256": sha256_bytes(canonical_bytes(stimulus)),
        "protocol_sha256": sha256_file(paths["protocol"]),
        "rubric_sha256": sha256_file(paths["rubric"]),
        "intervention_sha256": sha256_bytes(canonical_bytes(intervention)),
    }
    stimulus["stimulus_sha256"] = declared_stimulus
    intervention["intervention_sha256"] = declared_intervention
    for key, value in observed.items():
        if value != campaign.get(key):
            raise ValueError(f"Hash da entrada congelada divergiu: {key}")
    if declared_stimulus != observed["stimulus_sha256"]:
        raise ValueError("Hash interno do estimulo congelado divergiu.")
    if declared_intervention != observed["intervention_sha256"]:
        raise ValueError("Hash interno da intervencao congelada divergiu.")
    context_mode = validate_context_mode(intervention["context_mode"])
    if context_mode != campaign.get("context_mode"):
        raise ValueError("O context_mode congelado difere do manifesto da campanha.")
    if intervention.get("full_context_sha256") != campaign.get("full_context_sha256"):
        raise ValueError("O hash do contexto global difere do manifesto da campanha.")
    return {
        "scenario": stimulus["scenario"],
        "scenario_description": stimulus["scenario_description"],
        "scenario_config_h": stimulus["config_h"],
        "scenario_components": stimulus["components"],
        "scenario_main_c": stimulus["main_c"],
        "protocol": load_yaml(paths["protocol"]),
        "rubric": load_yaml(paths["rubric"]),
        "context_mode": context_mode,
        "intervention": intervention,
    }
