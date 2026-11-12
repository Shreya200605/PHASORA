
import time
import uuid
import os
import secrets

from policy.policy_engine import PolicyEngine
from policy.financial_transform import FinancialTransformer
from security.privacy_controller import PrivacyController
from audit.receipt import PrivacyReleaseReceipt


class GatewayProcessor:

    def __init__(self, detector, llm_client, reinserter):

        self.detector = detector
        self.llm_client = llm_client
        self.reinserter = reinserter

        self.policy_engine = PolicyEngine()
        self.transformer = FinancialTransformer()
        self.privacy_controller = PrivacyController()
        self.receipt_generator = PrivacyReleaseReceipt()

        self.hmac_secret = (
            os.getenv("PHASORA_HMAC_SECRET")
            or secrets.token_hex(32)
        )

    def process(self, user_prompt, purpose="general"):

        request_id = str(uuid.uuid4())
        start_time = time.perf_counter()

        mapping = {}

        try:
            detected_entities = self.detector.detect(user_prompt)

            decisions = self.policy_engine.evaluate(
                detected_entities,
                purpose
            )

            replacements = []
            placeholder_counters = {}
            placeholder_cache = {}

            normalized_purpose = purpose.lower().strip()

            income_entities = [
                entity for entity in detected_entities
                if entity["entity_type"].upper() == "INCOME"
            ]

            emi_entities = [
                entity for entity in detected_entities
                if entity["entity_type"].upper() == "EMI"
            ]

            financial_pair = None

            if (
                normalized_purpose in {"loan", "insurance"}
                and len(income_entities) == 1
                and len(emi_entities) == 1
            ):

                financial_pair = self.transformer.assess_finances(
                    income_entities[0]["value"],
                    emi_entities[0]["value"]
                )

                if (
                    financial_pair["income_band"] == "Unknown"
                    or financial_pair["emi_burden"] == "Unknown"
                ):
                    financial_pair = None

            for entity, decision in zip(
                detected_entities,
                decisions
            ):

                entity_type = entity["entity_type"].upper()
                value = entity["value"]
                action = decision["action"]

                if action == "BLOCK":
                    raise ValueError(
                        "Request blocked by privacy policy."
                    )

                if action == "RETAIN":
                    continue

                if action == "MASK":

                    replacement = self._create_placeholder(
                        entity_type,
                        value,
                        mapping,
                        placeholder_counters,
                        placeholder_cache
                    )

                elif action == "TRANSFORM":

                    if entity_type == "INCOME" and financial_pair:
                        replacement = financial_pair["income_band"]

                    elif entity_type == "EMI" and financial_pair:
                        replacement = financial_pair["emi_burden"]

                    else:
                        replacement = self.transformer.transform(
                            entity_type,
                            value
                        )

                        if (
                            str(replacement) == value
                            or entity_type == "EMI"
                        ):
                            replacement = self._create_placeholder(
                                entity_type,
                                value,
                                mapping,
                                placeholder_counters,
                                placeholder_cache
                            )

                elif action == "GENERALIZE":

                    if entity_type in {"AGE", "INCOME"}:

                        replacement = self.transformer.transform(
                            entity_type,
                            value
                        )

                        if str(replacement) == value:
                            replacement = self._create_placeholder(
                                entity_type,
                                value,
                                mapping,
                                placeholder_counters,
                                placeholder_cache
                            )

                    elif entity_type == "ADDRESS":
                        replacement = "generalized location"

                    else:
                        replacement = self._create_placeholder(
                            entity_type,
                            value,
                            mapping,
                            placeholder_counters,
                            placeholder_cache
                        )

                else:

                    replacement = self._create_placeholder(
                        entity_type,
                        value,
                        mapping,
                        placeholder_counters,
                        placeholder_cache
                    )

                replacements.append((
                    entity["start"],
                    entity["end"],
                    str(replacement)
                ))

            selected = []
            last_end = -1

            for start, end, replacement in sorted(
                replacements,
                key=lambda item: (item[0], -(item[1] - item[0]))
            ):

                if start >= last_end:
                    selected.append((start, end, replacement))
                    last_end = end

            sanitized_prompt = user_prompt

            for start, end, replacement in reversed(selected):
                sanitized_prompt = (
                    sanitized_prompt[:start]
                    + replacement
                    + sanitized_prompt[end:]
                )

            outbound_security = (
                self.privacy_controller.validate_outbound(
                    sanitized_prompt,
                    detected_entities,
                    decisions
                )
            )

            if not outbound_security["approved"]:
                raise ValueError(outbound_security["reason"])

            mapping_signature = (
                self.privacy_controller.integrity.sign_mapping(
                    mapping,
                    self.hmac_secret
                )
            )

            llm_response = self.llm_client.generate(
                sanitized_prompt
            )

            response_security = (
                self.privacy_controller.validate_response(
                    llm_response,
                    mapping.keys()
                )
            )

            if not response_security["approved"]:
                raise ValueError(
                    "LLM response failed placeholder security checks."
                )

            mapping_verified = (
                self.privacy_controller.integrity.verify_mapping(
                    mapping,
                    mapping_signature,
                    self.hmac_secret
                )
            )

            response_security["mapping_integrity"] = {
                "safe": mapping_verified,
                "algorithm": "HMAC-SHA256"
            }

            if not mapping_verified:
                raise ValueError(
                    "Placeholder mapping integrity verification failed."
                )

            final_response = self.reinserter.restore(
                llm_response,
                mapping
            )

            latency_ms = round(
                (time.perf_counter() - start_time) * 1000,
                2
            )

            model_name = getattr(
                self.llm_client,
                "model",
                self.llm_client.__class__.__name__
            )

            receipt = self.receipt_generator.generate(
                request_id,
                decisions,
                outbound_security,
                model_name
            )

            receipt["purpose"] = purpose
            receipt["latency_ms"] = latency_ms
            receipt["mapping_integrity"] = (
                "VERIFIED" if mapping_verified else "FAILED"
            )

            return {
                "request_id": request_id,
                "original_prompt": user_prompt,
                "sanitized_prompt": sanitized_prompt,
                "final_response": final_response,
                "detected_entities": detected_entities,
                "decisions": decisions,
                "security": outbound_security,
                "response_security": response_security,
                "receipt": receipt
            }

        finally:
            mapping.clear()

    @staticmethod
    def _create_placeholder(
        entity_type,
        value,
        mapping,
        counters,
        cache
    ):

        key = (entity_type, value)

        if key in cache:
            return cache[key]

        counters[entity_type] = counters.get(entity_type, 0) + 1

        placeholder = (
            f"<{entity_type}_{counters[entity_type]}>"
        )

        mapping[placeholder] = value
        cache[key] = placeholder

        return placeholder
